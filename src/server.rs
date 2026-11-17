//! `vault daemon`: the vault's background part, run as the owner by the LaunchAgent
//! `com.volgenic.vault` in his login (macOS) or the systemd user service `volgenic-vault.service`,
//! which lingering starts at boot (Linux). It reads the vault key, opens the socket and serves.
//! It is the only process that reads or changes the vault (R13), and the only one that writes
//! the local backups (R32). Callers must be the owner's own user ID (R22): `getpeereid` on
//! macOS, `SO_PEERCRED` on Linux (`platform::peer_of`).

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::Zeroizing;

use crate::audit::{self, AuditEvent};
use crate::backup;
use crate::secret::WipingBuf;
use crate::error::VaultError;
use crate::fill;
use crate::health::HealthBook;
use crate::keyprotect;
use crate::kinds::{self, HealthState, Refresher, Renewed};
use crate::model::{Kind, MirrorState, Record, SecretRef, VaultDoc};
use crate::platform::{self, Peer};
use crate::protocol::{
    self, AddReply, AddSealedReply, AuditReply, BackupReply, ClaimReply, ConfirmKitReply, Envelope, ErrorReply, Framed,
    HealthReply, ImportLoginReply, ImportReply, ImportedLogin, ImportedPlan, ListReply, MirrorPlanReply, OkReply,
    CancelReply, LeaseReply, LeasedSecret, ProxyReplyOut, ReadBackupReply, RenameReply, Request, ResetReply, RestoreReply, SignReply,
    SignedTx, StatusReply, TotpReply, VerifyBackupReply, WalletReply,
};
use crate::proxy::{self, ProxyRequest};
use crate::rules;
use crate::store::{self, OwnerPaths, Paths};
use crate::stream::{self, Streamer};
use crate::vault::{self, ImportOutcome, NewSecret, Vault};
use crate::intake;
use crate::lease;
use crate::wallet::{self, CancelArgs, SignArgs};

/// After a renewal that failed (not refused), the vault sends none for that login for this long,
/// so calls during a token server's outage don't each send one.
const RENEW_RETRY: Duration = Duration::from_secs(60);
/// After a renewal that worked, an early one (the login due but not expired) waits this long, so
/// a provider whose tokens last less than the kind's `ahead_secs` isn't renewed every minute.
const RENEW_EARLY_GAP: Duration = Duration::from_secs(3600);

/// Streamed model calls hold their connection for minutes, so there is room for many at once.
const MAX_CONNECTIONS: usize = 128;

struct Server {
    paths: Paths,
    owner_uid: u32,
    /// The mirror folder a restored-from-file vault gets: the owner's iCloud Drive on macOS.
    default_mirror_dir: PathBuf,
    /// The open vault, or none (before a restore). Every change and backup holds this lock, so
    /// changes happen one at a time (R13).
    vault: Mutex<Option<Vault>>,
    /// A read-only copy for agents' requests (list, 2FA, proxy), replaced after every change.
    snapshot: RwLock<Option<Arc<VaultDoc>>>,
    client: reqwest::blocking::Client,
    /// The async client and runtime for `stream` (R39).
    streamer: Streamer,
    /// What upstream replies said about each credential (`health`).
    health: Mutex<HealthBook>,
    /// How far the audit chain has been checked (R29), so `vault status`, which the host polls,
    /// checks only the lines written since. Taken after `vault`, never before it.
    audit_check: Mutex<audit::Checkpoint>,
    /// One lock per login the vault renews, by secret id: one renewal of a login at a time, so
    /// two calls that find it due never spend the same refresh token twice (`renew_login`).
    renewing: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// The last renewal attempt of each login, by secret id: when, and whether it worked
    /// (`renew_login`'s back-off).
    last_renewal: Mutex<HashMap<String, (std::time::Instant, bool)>>,
    active: AtomicUsize,
}

fn log(message: &str) {
    eprintln!("{} vault daemon: {message}", crate::now_rfc3339());
}

pub fn run() -> Result<(), VaultError> {
    let owner_uid = unsafe { libc::getuid() };
    if owner_uid == 0 {
        return Err(VaultError::Io("the vault runs as its owner, never as root".into()));
    }
    let paths = Paths::current();
    unsafe {
        libc::umask(0o077);
        // R11, R15: no environment variable changes which certificates the proxy trusts. On
        // Linux the system's root certificates are read by rustls-native-certs, which would
        // otherwise honour these two. Nothing else runs yet, so changing the environment is safe.
        std::env::remove_var("SSL_CERT_FILE");
        std::env::remove_var("SSL_CERT_DIR");
    }
    // On Linux systemd makes the socket's folder (`RuntimeDirectory=volgenic`, 0700) before it
    // starts the daemon. Run any other way (by hand, or with no systemd), the daemon makes it.
    #[cfg(not(target_os = "macos"))]
    if fs::symlink_metadata(&paths.socket_dir).is_err() {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&paths.socket_dir)?;
    }
    for dir in [&paths.dir, &paths.local_backups, &paths.socket_dir] {
        store::check_dir(dir, owner_uid, 0o077)?;
    }
    let opened = if store::vault_exists(&paths) {
        let (vault, migrated) = Vault::open(&paths)?;
        if let Some(note) = migrated {
            log(&note);
        }
        Some(vault)
    } else {
        None
    };
    let default_mirror_dir = OwnerPaths::for_uid(owner_uid)?.default_mirror_dir();

    let client = proxy::client()?;
    let streamer = Streamer::new()?;
    let health = fs::read(&paths.health_state).map(|bytes| HealthBook::from_json(&bytes)).unwrap_or_default();
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
    // Only the owner can reach it: the folder is 0700, and every caller is checked (R22).
    log(&format!("vault key: {}", keyprotect::describe(&paths.dir)));
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;

    let snapshot = match &opened {
        Some(vault) => Some(Arc::new(vault.read_copy()?)),
        None => None,
    };
    // The full check of the audit chain, across every rotated file, once at the start; from
    // here on `status` and `audit` check only what was written since (`audit::check`).
    let mut audit_check = audit::Checkpoint::default();
    let started = std::time::Instant::now();
    match audit::check(&paths.audit_log, &mut audit_check, opened.as_ref().map(Vault::audit_head)) {
        Ok(()) => log(&format!(
            "audit log: {} lines in {} file(s), hash chain intact (checked in {} ms)",
            audit_check.lines(),
            audit_check.files(),
            started.elapsed().as_millis()
        )),
        Err(error) => log(&format!("AUDIT LOG PROBLEM: {error}")),
    }
    let server = Arc::new(Server {
        paths: paths.clone(),
        owner_uid,
        default_mirror_dir,
        vault: Mutex::new(opened),
        snapshot: RwLock::new(snapshot),
        client,
        streamer,
        health: Mutex::new(health),
        audit_check: Mutex::new(audit_check),
        renewing: Mutex::new(HashMap::new()),
        last_renewal: Mutex::new(HashMap::new()),
        active: AtomicUsize::new(0),
    });
    let mut event = AuditEvent::new("daemon", "started");
    event.detail = Some(format!(
        "pid {}, as user ID {}, vault {}, socket {}",
        std::process::id(),
        owner_uid,
        if server.snapshot.read().map(|s| s.is_some()).unwrap_or(false) { "open" } else { "absent" },
        paths.socket.display()
    ));
    audit::append(&paths.audit_log, event)?;
    log(&format!("serving on {}", paths.socket.display()));

    // A vault just made by `vault install`, or one whose last backup failed: back it up now.
    let _ = server.with_vault(|vault| {
        if let Some(status) = vault.backup_if_needed() {
            log(&format!("backup of generation {}: {}", status.generation, if status.ok { "ok" } else { "FAILED" }));
        }
        Ok(())
    });

    // Token upkeep (R39): only kinds with a refresher need it (Codex and Grok logins; a Claude
    // plan has none).
    if kinds::any_refresher() {
        let server = Arc::clone(&server);
        std::thread::spawn(move || {
            loop {
                server.upkeep();
                std::thread::sleep(Duration::from_secs(60));
            }
        });
    }

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let server = Arc::clone(&server);
        if server.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            server.active.fetch_sub(1, Ordering::SeqCst);
            let mut stream = stream;
            let _ = reply(&mut stream, &Envelope::default(), &ErrorReply::from(&VaultError::Busy));
            continue;
        }
        std::thread::spawn(move || {
            server.handle(stream);
            server.active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
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

/// Reads the bytes that follow a request line: a `restore`'s backup file (ciphertext, at most
/// `backup::MAX_BACKUP_BYTES`) or a `stream`'s request body (at most `stream::MAX_BODY`):
/// exactly `len` bytes. Neither holds a stored value, so an ordinary buffer is fine.
fn read_payload(stream: &mut UnixStream, mut data: Vec<u8>, len: usize, max: usize) -> Result<Vec<u8>, VaultError> {
    if len > max {
        return Err(VaultError::BadRequest(if max == backup::MAX_BACKUP_BYTES {
            format!("the backup is over {} MiB, larger than any backup the vault writes", max / (1024 * 1024))
        } else {
            format!("the body is over {} MiB", max / (1024 * 1024))
        }));
    }
    if data.len() > len {
        data.truncate(len);
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let have = data.len();
    data.resize(len, 0);
    stream
        .read_exact(&mut data[have..])
        .map_err(|_| VaultError::BadRequest("the bytes after the request line ended early".into()))?;
    Ok(data)
}

/// Writes one reply line: the reply's fields plus this daemon's protocol version and the
/// request's id, echoed as it came (protocol 2).
fn reply<T: serde::Serialize>(stream: &mut UnixStream, envelope: &Envelope, value: &T) -> std::io::Result<()> {
    let framed = Framed { body: value, protocol: protocol::PROTOCOL_VERSION, request_id: envelope.request_id.as_ref() };
    let mut line = serde_json::to_vec(&framed).unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"encoding\"}".to_vec());
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()
}

/// Who sent a request: the peer (R22, R23) and the request's envelope (its protocol version and
/// request id).
/// A `stream` request, read.
struct StreamCall {
    secret: SecretRef,
    host: Option<String>,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    idle: u64,
}

struct Caller {
    peer: Peer,
    envelope: Envelope,
}

fn with_peer(mut event: AuditEvent, caller: &Caller) -> AuditEvent {
    event.peer_pid = caller.peer.pid;
    event.peer_program = caller.peer.program.clone();
    event.request_id = caller.envelope.request_id_text();
    event
}

fn error_reply(stream: &mut UnixStream, caller: &Caller, error: &VaultError) -> std::io::Result<()> {
    reply(stream, &caller.envelope, &ErrorReply::from(error))
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

    /// The audit log for `vault audit`, its chain checked up to the head the vault file records
    /// (R29): the last lines from the checkpoint, or with `all` every line and a full check of
    /// every file, which also renews the checkpoint. Lines hold no values (R28).
    fn audit_report(&self, all: bool) -> AuditReply {
        let recorded = self.snapshot().ok().map(|doc| doc.audit_head.clone());
        let recorded = recorded.as_deref();
        let log = &self.paths.audit_log;
        let result = if all {
            audit::read_all(log, recorded).map(|(lines, checkpoint)| {
                let total = checkpoint.lines();
                *self.audit_check.lock().unwrap_or_else(|e| e.into_inner()) = checkpoint;
                (total, lines)
            })
        } else {
            let mut checkpoint = self.audit_check.lock().unwrap_or_else(|e| e.into_inner());
            audit::check(log, &mut checkpoint, recorded).map(|()| (checkpoint.lines(), checkpoint.tail()))
        };
        match result {
            Ok((total, lines)) => AuditReply { ok: true, total, lines, problem: None },
            Err(error) => AuditReply { ok: true, total: 0, lines: Vec::new(), problem: Some(error.to_string()) },
        }
    }

    /// Best effort, for refusals and for lines after a use that is already recorded: not waited
    /// onto the disk, so a call's outcome line doesn't hold up the next call's line (R28 needs
    /// the line before a use on disk, which `record` flushes).
    fn audit(&self, event: AuditEvent) {
        if let Err(error) = audit::append_unsynced(&self.paths.audit_log, event) {
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
        peer: &Caller,
        op: &str,
        name: Option<&str>,
        result: Result<T, VaultError>,
    ) -> std::io::Result<()> {
        match result {
            Ok(value) => reply(stream, &peer.envelope, &value),
            Err(error) => {
                let mut event = AuditEvent::new(op, &format!("denied: {}", error.code()));
                event.name = name.map(str::to_string);
                if let VaultError::BackupFailed(why) | VaultError::InvalidRule(why) | VaultError::InvalidSecret(why) = &error {
                    event.detail = Some(why.clone());
                }
                self.audit(with_peer(event, peer));
                error_reply(stream, peer, &error)
            }
        }
    }

    fn handle(&self, mut stream: UnixStream) {
        // R22: only the owner's user ID. R23: the caller's pid and program are a hint.
        let Some(peer) = platform::peer_of(stream.as_raw_fd()) else { return };
        let mut peer = Caller { peer, envelope: Envelope::default() };
        if peer.peer.uid != self.owner_uid {
            let mut event = AuditEvent::new("connect", "denied: not the owner's user ID");
            event.detail = Some(format!("uid {}", peer.peer.uid));
            self.audit(with_peer(event, &peer));
            return;
        }
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

        let (line, rest) = match read_request_line(&mut stream) {
            Ok(read) => read,
            Err(error) => {
                self.audit(with_peer(AuditEvent::new("request", &format!("denied: {}", error.code())), &peer));
                let _ = error_reply(&mut stream, &peer, &error);
                return;
            }
        };
        let (envelope, accepted) = protocol::parse_envelope(line.as_slice());
        peer.envelope = envelope;
        if let Err(error) = accepted {
            self.audit(with_peer(AuditEvent::new("request", &format!("denied: {}", error.code())), &peer));
            let _ = error_reply(&mut stream, &peer, &error);
            return;
        }
        let request: Request = match protocol::parse_request(line.as_slice()) {
            Ok(request) => request,
            Err(_) => {
                // A fixed message: serde's own can quote a field's value, which may be a secret (R2).
                let error = VaultError::BadRequest("not a valid request; see the protocol in the README".into());
                self.audit(with_peer(AuditEvent::new("request", "denied: bad_request"), &peer));
                let _ = error_reply(&mut stream, &peer, &error);
                return;
            }
        };
        drop(line);
        // `restore FILE` sends the backup's bytes after the line (ciphertext only).
        let following = match &request {
            Request::Restore { backup_len: Some(len), .. } => Some(("restore", *len, backup::MAX_BACKUP_BYTES)),
            Request::Stream { body_len, .. } if *body_len > 0 => Some(("stream", *body_len, stream::MAX_BODY)),
            _ => None,
        };
        let payload = match following {
            Some((op, len, max)) => match read_payload(&mut stream, rest, len, max) {
                Ok(data) => Some(data),
                Err(error) => {
                    self.audit(with_peer(AuditEvent::new(op, &format!("denied: {}", error.code())), &peer));
                    let _ = error_reply(&mut stream, &peer, &error);
                    return;
                }
            },
            None => None,
        };
        let _ = self.dispatch(&mut stream, &peer, request, payload);
    }

    fn dispatch(
        &self,
        stream: &mut UnixStream,
        peer: &Caller,
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
            Request::Totp { secret } => {
                let result = self.snapshot().and_then(|doc| {
                    let (code, record) = vault::totp_code(&doc, &secret)?;
                    let mut event = AuditEvent::named("totp", &record.name, "ok");
                    event.secret_id = Some(record.id.clone());
                    self.record(with_peer(event, peer))?;
                    Ok(TotpReply {
                        ok: true,
                        id: record.id.clone(),
                        name: record.name.clone(),
                        code: code.code,
                        seconds_left: code.seconds_left,
                    })
                });
                self.finish(stream, peer, "totp", Some(&secret.label()), result)
            }
            Request::Proxy { secret, host, port, method, path, headers, body, body_base64 } => {
                match self.snapshot() {
                    Ok(doc) => match self.proxy(&doc, &secret, (host, port), method, path, headers, body, body_base64, peer) {
                        Ok(out) => reply(stream, &peer.envelope, &out),
                        Err(error) => error_reply(stream, peer, &error),
                    },
                    Err(error) => self.finish::<OkReply>(stream, peer, "proxy", Some(&secret.label()), Err(error)),
                }
            }
            Request::Stream { secret, host, method, path, headers, body_len: _, idle_timeout_secs } => {
                let idle = idle_timeout_secs.unwrap_or(stream::DEFAULT_IDLE_SECS).clamp(1, stream::MAX_IDLE_SECS);
                let call = StreamCall { secret, host, method, path, headers, body: payload.unwrap_or_default(), idle };
                self.stream(stream, peer, call)
            }
            Request::Health => {
                let result = self.snapshot().and_then(|doc| {
                    self.record(with_peer(AuditEvent::new("health", "ok"), peer))?;
                    let book = self.health.lock().unwrap_or_else(|e| e.into_inner());
                    Ok(HealthReply { ok: true, credentials: book.report(&doc, crate::now_unix()) })
                });
                self.finish(stream, peer, "health", None, result)
            }
            Request::AddSealed { name, kind, sealed_base64, replace } => {
                let result = (|| {
                    // R40: a sealed value may replace a stored one only for a kind whose hosts and
                    // headers the kind table fixes (`claude_plan`, `codex_login`, `grok_login`).
                    // Anyone can seal to the intake key, so replacing an API key's value would also
                    // replace its rule and could send that name's agent traffic to another host.
                    // A sealed login (a new sign-in) is the vault's to renew from the start.
                    if replace && kinds::spec(kind).is_none() {
                        return Err(VaultError::SealedInvalid(format!(
                            "a sealed value can't replace a stored {}; only a kind with fixed hosts (claude_plan, codex_login, grok_login) can be replaced this way",
                            kind.label()
                        )));
                    }
                    let doc = self.snapshot()?;
                    let identity = doc
                        .intake_identity
                        .as_ref()
                        .ok_or_else(|| VaultError::SealedInvalid("this vault has no intake key".into()))?;
                    let sealed = intake::open(identity, &sealed_base64, &name, kind)?;
                    drop(doc);
                    let rule = match (kind, &sealed.rule) {
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
                    let site = match (sealed.site, &rule) {
                        (Some(site), _) => site,
                        (None, Some(rule)) => rule.host.clone(),
                        (None, None) => String::new(),
                    };
                    let new = NewSecret {
                        name: sealed.name,
                        kind,
                        site,
                        rule,
                        username: sealed.username,
                        app: sealed.app,
                        leasable: sealed.leasable,
                        value: sealed.value,
                    };
                    self.with_vault(|vault| vault.put(new, replace))
                        .map(|(secret, backup, replaced)| AddSealedReply { ok: true, secret, replaced, backup })
                })();
                self.finish(stream, peer, "add_sealed", Some(&name), result)
            }
            Request::ImportPlan { plans } => {
                let result = self.with_vault(|vault| vault.import_plans(plans)).map(|(results, backup)| {
                    let plans = results
                        .into_iter()
                        .map(|(name, outcome)| match outcome {
                            ImportOutcome::Done(version) => ImportedPlan {
                                name,
                                result: "done".into(),
                                version: Some(version),
                                error: None,
                                message: None,
                            },
                            ImportOutcome::Unchanged(version) => ImportedPlan {
                                name,
                                result: "unchanged".into(),
                                version: Some(version),
                                error: None,
                                message: None,
                            },
                            ImportOutcome::Failed(error) => ImportedPlan {
                                name,
                                result: "failed".into(),
                                version: None,
                                error: Some(error.code().into()),
                                message: Some(error.to_string()),
                            },
                        })
                        .collect();
                    ImportReply { ok: true, plans, backup }
                });
                self.finish(stream, peer, "import_plan", None, result)
            }
            Request::ImportLogin { logins } => {
                let result = self.with_vault(|vault| vault.import_logins(logins)).map(|(results, backup)| {
                    let logins = results
                        .into_iter()
                        .map(|(name, kind, outcome, claimed)| {
                            let (result, version, error, message) = match outcome {
                                ImportOutcome::Done(version) => ("done", Some(version), None, None),
                                ImportOutcome::Unchanged(version) => ("unchanged", Some(version), None, None),
                                ImportOutcome::Failed(error) => ("failed", None, Some(error.code().to_string()), Some(error.to_string())),
                            };
                            ImportedLogin { name, kind, result: result.into(), version, claimed, error, message }
                        })
                        .collect();
                    ImportLoginReply { ok: true, logins, backup }
                });
                self.finish(stream, peer, "import_login", None, result)
            }
            Request::ClaimRefresh { secret, version } => {
                let result = self.with_vault(|vault| vault.claim_refresh(&secret, version)).map(|(secret, already, backup)| {
                    if already {
                        let mut event = AuditEvent::named("claim-refresh", &secret.name, "ok: already claimed");
                        event.secret_id = Some(secret.id.clone());
                        self.audit(with_peer(event, peer));
                    }
                    ClaimReply { ok: true, secret, claimed: true, already, backup }
                });
                self.finish(stream, peer, "claim_refresh", Some(&secret.label()), result)
            }
            Request::Status => {
                let guard = self.vault.lock().unwrap_or_else(|e| e.into_inner());
                let opened = guard.as_ref().map(|vault| {
                    let mut checkpoint = self.audit_check.lock().unwrap_or_else(|e| e.into_inner());
                    match audit::check(&self.paths.audit_log, &mut checkpoint, Some(vault.audit_head())) {
                        Ok(()) => vault.status(Ok(&checkpoint)),
                        Err(error) => vault.status(Err(error.to_string())),
                    }
                });
                drop(guard);
                let mirror = fs::read(&self.paths.mirror_state)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<MirrorState>(&bytes).ok());
                self.audit(with_peer(AuditEvent::new("status", "ok"), peer));
                reply(
                    stream,
                    &peer.envelope,
                    &StatusReply {
                        ok: true,
                        version: crate::VERSION.into(),
                        format: crate::model::VAULT_FORMAT,
                        pid: std::process::id(),
                        uid: unsafe { libc::getuid() },
                        key_protection: keyprotect::describe(&self.paths.dir),
                        local_backups: self.paths.local_backups.display().to_string(),
                        restore_point: vault::has_restore_point(&self.paths),
                        vault: opened,
                        mirror,
                    },
                )
            }
            Request::Audit { all } => {
                let report = self.audit_report(all);
                self.audit(with_peer(AuditEvent::new("audit", "ok"), peer));
                reply(stream, &peer.envelope, &report)
            }
            Request::Lease { job, recipient, secrets, ttl_seconds } => {
                self.lease(stream, peer, &job, &recipient, &secrets, ttl_seconds)
            }
            Request::Sign { secret, fields } => self.sign(stream, peer, &secret, &fields.args()),
            Request::SignCancel {
                secret,
                chain,
                extra,
                gas_limit,
                nonce,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                ladder,
                ladder_max_fee_per_gas,
                on_behalf_of,
            } => {
                let args = CancelArgs {
                    chain: &chain,
                    extra,
                    gas_limit,
                    nonce,
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    ladder,
                    ladder_max_fee_per_gas,
                    on_behalf_of: on_behalf_of.as_deref(),
                };
                self.sign_cancel(stream, peer, &secret, &args)
            }
            Request::Fill { secret, origin, fields, engine, tab, on_behalf_of } => {
                let notes = [fill::note(engine), fill::note(tab), fill::note(on_behalf_of)];
                self.fill(stream, peer, &secret, &origin, &fields, &notes)
            }
            Request::GenerateLogin { name, site, username, length } => {
                let result = self
                    .with_vault(|vault| vault.generate_login(&name, &site, &username, length))
                    .map(|(secret, backup)| AddReply { ok: true, secret, backup });
                self.finish(stream, peer, "generate-login", Some(&name), result)
            }
            Request::WalletCreate { name, chain, caps, recovery_key } => {
                let result = wallet::Chain::parse(&chain).and_then(|chain| {
                    self.with_vault(|vault| vault.create_wallet(&name, chain, caps, recovery_key))
                        .map(|(secret, backup)| WalletReply { ok: true, secret, backup })
                });
                self.finish(stream, peer, "wallet-create", Some(&name), result)
            }
            Request::WalletCaps { secret, caps, recovery_key } => {
                let result = self
                    .with_vault(|vault| vault.set_wallet_caps(&secret, caps, recovery_key))
                    .map(|(secret, backup)| WalletReply { ok: true, secret, backup });
                self.finish(stream, peer, "wallet-caps", Some(&secret.label()), result)
            }
            Request::Add { name, kind, site, rule, username, app, leasable, value } => {
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
                    let new = NewSecret { name: name.clone(), kind, site, rule, username, app, leasable, value };
                    self.with_vault(|vault| vault.add(new))
                        .map(|(secret, backup)| AddReply { ok: true, secret, backup })
                })();
                self.finish(stream, peer, "add", Some(&name), result)
            }
            Request::Delete { secret } => {
                let result = self.with_vault(|vault| vault.delete(&secret)).map(|backup| BackupReply { ok: true, backup });
                self.finish(stream, peer, "delete", Some(&secret.label()), result)
            }
            Request::Rename { secret, new_name } => {
                let result = self
                    .with_vault(|vault| vault.rename(&secret, &new_name))
                    .map(|(secret, backup)| RenameReply { ok: true, secret, backup });
                self.finish(stream, peer, "rename", Some(&secret.label()), result)
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
                        vault::restore(&self.paths, file, &self.default_mirror_dir, recovery_key)?;
                    // The vault is on disk now: hold it even if its first backup fails, so the
                    // daemon and the disk agree (the failure is the alarm of R19).
                    let backup = restored.backup();
                    *guard = Some(restored);
                    self.publish(&guard);
                    let backup = backup?;
                    Ok(RestoreReply {
                        ok: true,
                        vault_id: report.vault_id,
                        vault_identity: report.vault_identity,
                        from_vault_id: report.from_vault_id,
                        from_format: report.from_format,
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

    /// `lease` (#7446): seals each named leasable app secret to the job's own key, with the job and
    /// the expiry inside, and answers ciphertext only. One audit line per secret (its name and id,
    /// the job, the recipient key's fingerprint, the expiry, the caller), flushed to disk before
    /// the answer leaves (R28); no line, no lease. A refusal is one line naming the refused secrets.
    fn lease(
        &self,
        out: &mut UnixStream,
        peer: &Caller,
        job: &str,
        recipient: &str,
        secrets: &[SecretRef],
        ttl_seconds: u64,
    ) -> std::io::Result<()> {
        let result = (|| -> Result<LeaseReply, VaultError> {
            let terms = lease::terms(job, recipient, ttl_seconds, crate::now_unix())?;
            lease::check_secrets(secrets)?;
            let doc = self.snapshot()?;
            let (records, missing) = lease::choose(&doc, secrets)?;
            let mut sealed = Vec::with_capacity(records.len());
            for record in &records {
                sealed.push(LeasedSecret {
                    name: record.name.clone(),
                    id: record.id.clone(),
                    sealed_base64: lease::seal(record, &terms)?,
                });
            }
            for record in &records {
                let mut event = AuditEvent::named("lease", &record.name, "ok");
                event.secret_id = Some(record.id.clone());
                event.detail = Some(terms.describe());
                self.record(with_peer(event, peer))?;
            }
            if records.is_empty() {
                let mut event = AuditEvent::new("lease", "ok: nothing held");
                event.detail = Some(format!("{}; none of the names is in the vault", terms.describe()));
                self.audit(with_peer(event, peer));
            }
            Ok(LeaseReply { ok: true, sealed, missing, expires_at: terms.expires_at.clone(), job: terms.job.clone() })
        })();
        match result {
            Ok(reply_value) => reply(out, &peer.envelope, &reply_value),
            Err(error) => {
                let mut event = AuditEvent::new("lease", &format!("denied: {}", error.code()));
                let shown_job: String = job.chars().filter(|c| !c.is_control()).take(lease::MAX_JOB_CHARS).collect();
                event.detail = Some(format!("job {shown_job:?}: {error}"));
                if let VaultError::NotLeasable(names) = &error {
                    event.name = Some(names.join(", "));
                }
                self.audit(with_peer(event, peer));
                error_reply(out, peer, &error)
            }
        }
    }

    /// `fill` (#7663, R37): a login's values for the browser engine that types them, only when the
    /// frame holding the fields is `https:` on the login's registrable domain. The `fill` line
    /// (the login's name and id, the fields, the frame's host, the engine, the tab, for whom, the
    /// caller) is flushed to disk before the answer leaves (R28); no line, no values. A refusal is
    /// one `fill denied: <code>` line. The reply is written by hand into a wiped buffer (R1).
    fn fill(
        &self,
        out: &mut UnixStream,
        peer: &Caller,
        secret: &SecretRef,
        origin: &str,
        fields: &[String],
        notes: &[Option<String>; 3],
    ) -> std::io::Result<()> {
        let [engine, tab, on_behalf_of] = notes;
        let result = (|| -> Result<WipingBuf, VaultError> {
            let fields = fill::parse_fields(fields)?;
            let doc = self.snapshot()?;
            let record = doc.find_ref(secret);
            let matched = fill::check(record, &secret.label(), origin)?;
            let record = record.ok_or(VaultError::VaultFileCorrupt)?;
            let line = fill::reply_line(record, &fields, &matched, &peer.envelope)?;
            let mut event = AuditEvent::named("fill", &record.name, "ok");
            event.secret_id = Some(record.id.clone());
            event.host = Some(matched.host.clone());
            event.detail = Some(fill::describe(&fields, &matched, engine.as_deref(), tab.as_deref(), on_behalf_of.as_deref()));
            self.record(with_peer(event, peer))?;
            Ok(line)
        })();
        match result {
            Ok(line) => {
                out.write_all(line.as_slice())?;
                out.flush()
            }
            Err(error) => {
                let mut event = AuditEvent::new("fill", &format!("denied: {}", error.code()));
                event.name = Some(secret.label());
                let mut detail = error.to_string();
                for note in [engine, tab, on_behalf_of].into_iter().flatten() {
                    detail.push_str(&format!("; {note}"));
                }
                event.detail = Some(detail);
                self.audit(with_peer(event, peer));
                error_reply(out, peer, &error)
            }
        }
    }

    /// `sign` (#7440, #7490): one token transfer the vault builds from structured fields, within
    /// the wallet's caps, signed (on Ethereum with its ladder). The `sign` line (chain, token,
    /// amount, recipient, the chain's terms, hash, the caller) is written with the change that
    /// records the payment, and an Ethereum ladder's `sign-ladder` line (how many rungs, the top
    /// fee, the worst-case fee, the hashes) is flushed to disk after it: both before the answer
    /// leaves (R28); no line, no signature. A refusal is one `sign denied: <code>` line.
    fn sign(&self, out: &mut UnixStream, peer: &Caller, secret: &SecretRef, args: &SignArgs<'_>) -> std::io::Result<()> {
        let result = (|| -> Result<SignReply, VaultError> {
            let outcome = self.with_vault(|vault| vault.sign_payment(secret, args, |event| with_peer(event, peer)))?;
            let payment = &outcome.payment;
            let family = payment.chain.family();
            if let (wallet::Plan::Evm(plan), false) = (&payment.plan, outcome.signatures.ladder.is_empty()) {
                let top = payment.top().unwrap_or(plan.first);
                let mut event = AuditEvent::named("sign-ladder", &outcome.summary.name, "ok");
                event.secret_id = Some(outcome.summary.id.clone());
                event.detail = Some(format!(
                    "{} replacement(s) of {} {} {} to {} at nonce {}: top max fee {} gwei/gas, worst-case fee {}; hashes {}",
                    outcome.signatures.ladder.len(),
                    payment.chain.label(),
                    payment.amount_text(),
                    payment.token.label(),
                    payment.to_text,
                    plan.nonce,
                    wallet::decimal(top.max_fee_per_gas as u128, 9),
                    family.fee_text(payment.worst_fee()),
                    outcome.signatures.ladder.iter().map(|signed| signed.hash.clone()).collect::<Vec<_>>().join(", ")
                ));
                self.record(with_peer(event, peer))?;
            }
            let out_tx = |signed: &wallet::SignedTx| SignedTx {
                raw: signed.raw.clone(),
                hash: signed.hash.clone(),
                max_fee_per_gas: signed.fees.map(|fees| fees.max_fee_per_gas),
                max_priority_fee_per_gas: signed.fees.map(|fees| fees.max_priority_fee_per_gas),
                raw_data_hex: signed.raw_data_hex.clone(),
            };
            let wallet = outcome.summary.wallet.as_ref().ok_or(VaultError::VaultFileCorrupt)?;
            let evm = family == wallet::Family::Evm;
            let mut reply = SignReply {
                ok: true,
                id: outcome.summary.id.clone(),
                name: outcome.summary.name.clone(),
                chain: payment.chain,
                chain_id: payment.chain.chain_id(),
                from: wallet.checksummed.clone(),
                to: payment.to_text.clone(),
                token: payment.token,
                contract: payment.contract_text.clone(),
                amount: payment.amount_text(),
                nonce: None,
                gas_limit: None,
                source_token_account: None,
                recipient_token_account: None,
                recent_blockhash: None,
                creates_recipient_account: None,
                expiration: None,
                fee_limit: None,
                signed: out_tx(&outcome.signatures.first),
                ladder: outcome.signatures.ladder.iter().map(out_tx).collect(),
                worst_fee: payment.worst_fee(),
                fee_unit: family.fee_unit().to_string(),
                replacement: outcome.counted.replaces.is_some(),
                counted_micros: outcome.counted.micros,
                counted_fees: outcome.counted.fee,
                caps: wallet.caps,
                spent_today_micros: wallet.spent_today_micros,
                fees_today: wallet.fees_today,
                worst_fee_wei: evm.then_some(payment.worst_fee()),
                counted_fees_wei: evm.then_some(outcome.counted.fee),
                fees_today_wei: evm.then_some(wallet.fees_today),
                backup: outcome.backup,
            };
            match &payment.plan {
                wallet::Plan::Evm(plan) => {
                    reply.nonce = Some(plan.nonce);
                    reply.gas_limit = Some(plan.gas_limit);
                }
                wallet::Plan::Solana(transfer) => {
                    reply.source_token_account = Some(crate::solana::address_text(&transfer.source()?));
                    reply.recipient_token_account = Some(crate::solana::address_text(&transfer.destination()?));
                    reply.recent_blockhash = Some(crate::solana::address_text(&transfer.recent_blockhash));
                    reply.creates_recipient_account = Some(transfer.create_recipient_account);
                }
                wallet::Plan::Tron(transfer) => {
                    reply.expiration = Some(transfer.expiration);
                    reply.fee_limit = Some(transfer.fee_limit);
                }
            }
            Ok(reply)
        })();
        match result {
            Ok(reply_value) => reply(out, &peer.envelope, &reply_value),
            Err(error) => {
                let mut event = AuditEvent::new("sign", &format!("denied: {}", error.code()));
                event.name = Some(secret.label());
                let shown_to: String = args.to.chars().filter(|c| !c.is_control()).take(64).collect();
                let shown_amount: String = args.amount.chars().filter(|c| !c.is_control()).take(40).collect();
                let shown_token: String = args.token.chars().filter(|c| !c.is_control()).take(8).collect();
                let shown_chain: String = args.chain.chars().filter(|c| !c.is_control()).take(16).collect();
                let shown_for: String =
                    args.on_behalf_of.unwrap_or("").chars().filter(|c| !c.is_control()).take(wallet::MAX_LABEL_CHARS).collect();
                event.detail = Some(format!(
                    "{shown_chain} {shown_amount} {shown_token} to {shown_to}{}{}: {error}",
                    args.nonce.map(|nonce| format!(" at nonce {nonce}")).unwrap_or_default(),
                    if shown_for.is_empty() { String::new() } else { format!(", for {shown_for}") }
                ));
                self.audit(with_peer(event, peer));
                error_reply(out, peer, &error)
            }
        }
    }

    /// `sign` with `cancel` (#7491): a 0-ETH transfer from the wallet to itself at a payment's
    /// nonce, and its ladder. Its one `sign-cancel` line (the nonce, the fees, what it cancels,
    /// every hash, the caller) is written with the change and flushed before the answer leaves
    /// (R28). A refusal is one `sign-cancel denied: <code>` line.
    fn sign_cancel(&self, out: &mut UnixStream, peer: &Caller, secret: &SecretRef, args: &CancelArgs<'_>) -> std::io::Result<()> {
        let result = (|| -> Result<CancelReply, VaultError> {
            let outcome = self.with_vault(|vault| vault.sign_cancel(secret, args, |event| with_peer(event, peer)))?;
            let cancel = &outcome.cancel;
            let out_tx = |fees: wallet::Fees, signed: &crate::evm::Signed| SignedTx {
                raw: format!("0x{}", hex::encode(&signed.raw)),
                hash: format!("0x{}", hex::encode(signed.hash)),
                max_fee_per_gas: Some(fees.max_fee_per_gas),
                max_priority_fee_per_gas: Some(fees.max_priority_fee_per_gas),
                raw_data_hex: None,
            };
            let wallet = outcome.summary.wallet.as_ref().ok_or(VaultError::VaultFileCorrupt)?;
            Ok(CancelReply {
                ok: true,
                cancel: true,
                id: outcome.summary.id.clone(),
                name: outcome.summary.name.clone(),
                chain: cancel.chain,
                chain_id: cancel.chain.chain_id().unwrap_or(0),
                from: wallet.checksummed.clone(),
                to: wallet.checksummed.clone(),
                nonce: cancel.nonce,
                gas_limit: wallet::CANCEL_GAS,
                cancels: cancel.cancels.clone(),
                signed: out_tx(cancel.first, &outcome.signed),
                ladder: outcome.ladder.iter().map(|(fees, signed)| out_tx(*fees, signed)).collect(),
                worst_fee_wei: cancel.worst_fee_wei(),
                counted_fees_wei: outcome.counted.fee,
                caps: wallet.caps,
                spent_today_micros: wallet.spent_today_micros,
                fees_today_wei: wallet.fees_today,
                backup: outcome.backup,
            })
        })();
        match result {
            Ok(reply_value) => reply(out, &peer.envelope, &reply_value),
            Err(error) => {
                let mut event = AuditEvent::new("sign-cancel", &format!("denied: {}", error.code()));
                event.name = Some(secret.label());
                let shown_chain: String = args.chain.chars().filter(|c| !c.is_control()).take(16).collect();
                let shown_for: String =
                    args.on_behalf_of.unwrap_or("").chars().filter(|c| !c.is_control()).take(wallet::MAX_LABEL_CHARS).collect();
                event.detail = Some(format!(
                    "{shown_chain} cancel at nonce {}, max fee {} gwei/gas{}: {error}",
                    args.nonce,
                    wallet::decimal(args.max_fee_per_gas as u128, 9),
                    if shown_for.is_empty() { String::new() } else { format!(", for {shown_for}") }
                ));
                self.audit(with_peer(event, peer));
                error_reply(out, peer, &error)
            }
        }
    }

    /// `stream` (R39): checks, the audit line before the credential leaves the vault (R28), the
    /// call, and the line after it with what happened. For a login the vault renews (claimed,
    /// and not refused): renewed first when it is due, and when the upstream answers 401, the
    /// 401 is held back, the login renewed and the call made once more with the new token.
    fn stream(&self, out: &mut UnixStream, peer: &Caller, call: StreamCall) -> std::io::Result<()> {
        let mut doc = match self.snapshot() {
            Ok(doc) => doc,
            Err(error) => return self.finish::<OkReply>(out, peer, "stream", Some(&call.secret.label()), Err(error)),
        };
        let logged_path: String = call.path.split(['?', '#']).next().unwrap_or("").chars().take(200).collect();
        let record = doc.find_ref(&call.secret);
        let mut event = AuditEvent::named("stream", &record.map_or_else(|| call.secret.label(), |r| r.name.clone()), "");
        event.secret_id = record.map(|r| r.id.clone());
        event.method = Some(call.method.chars().take(16).collect());
        event.path = Some(logged_path);
        let mut event = with_peer(event, peer);
        let refuse = |error: VaultError, mut event: AuditEvent, out: &mut UnixStream| {
            event.outcome = format!("denied: {}", error.code());
            if let VaultError::RuleMismatch(why) | VaultError::BadRequest(why) | VaultError::UpstreamFailed(why) = &error {
                event.detail = Some(why.clone());
            }
            self.audit(event);
            error_reply(out, peer, &error)
        };
        let Some(record) = record else {
            return refuse(call.secret.not_found(), event, out);
        };
        let id = record.id.clone();
        let plan = match stream::plan(record, call.host.as_deref(), &call.method, &call.path, &call.headers) {
            Ok(plan) => plan,
            Err(error) => return refuse(error, event, out),
        };
        event.host = Some(plan.host.clone());
        // Token upkeep before the call: a login that is due is renewed first.
        if let Some(refresher) = self.renewable(record) {
            let now = crate::now_unix();
            if refresher.due(record.expires_at, now) {
                match self.renew_login(&id, record.version, "due, before a call", true) {
                    Ok(fresh) => doc = fresh,
                    Err(VaultError::CredentialRefused) => return refuse(VaultError::CredentialRefused, event, out),
                    // The token it has may still work; the upkeep pass tries again.
                    Err(error) => log(&format!("couldn't renew a login before a call: {}", error.code())),
                }
            }
        }
        let mut renewed_after_401 = false;
        loop {
            let Some(record) = doc.records.iter().find(|record| record.id == id) else {
                return refuse(call.secret.not_found(), event, out);
            };
            let credential = match stream::Credential::of(record) {
                Ok(credential) => credential,
                Err(error) => return refuse(error, event, out),
            };
            // A login's 401 never reaches the caller as a bare 401 (Codex fails the turn on one,
            // Grok retries it four times): the vault renews and retries once when it may, and
            // otherwise answers one error line the host's proxy maps to "sign in again".
            let is_login = kinds::spec(record.kind).is_some_and(|spec| spec.refresher.is_some());
            // R28: the use is on disk before the credential leaves the vault. No line, no request.
            let mut attempt = event.clone();
            attempt.outcome = "sending".into();
            if let Err(error) = self.record(attempt) {
                return error_reply(out, peer, &error);
            }
            let outcome = self.streamer.run(
                &plan,
                &credential,
                &call.body,
                Duration::from_secs(call.idle),
                out,
                &peer.envelope,
                is_login,
            );
            drop(credential);
            if outcome.end == "auth_error" {
                let mut held = event.clone();
                held.status = Some(401);
                held.outcome = "held: auth_error".into();
                if !renewed_after_401 && self.renewable(record).is_some() {
                    // Nothing reached the caller: renew the login and make the call once more.
                    held.detail = Some("the upstream answered 401; renewing the login and trying once more".into());
                    self.audit(held);
                    renewed_after_401 = true;
                    match self.renew_login(&id, record.version, "the upstream answered 401", false) {
                        Ok(fresh) => {
                            doc = fresh;
                            continue;
                        }
                        Err(error) => return refuse(error, event, out),
                    }
                }
                // No renewal can help: the login isn't claimed yet (the vault may not renew it),
                // it was refused already, or a fresh token got a 401 too.
                let unclaimed = record.handover.as_ref().is_some_and(|handover| !handover.claimed);
                held.detail = Some("the upstream answered 401 and no renewal can fix it; answered as an error line, not a 401".into());
                self.audit(held);
                if unclaimed {
                    self.observe(record, HealthState::Expired, Some(401));
                    return refuse(VaultError::LoginAwaitingClaim, event, out);
                }
                self.observe(record, HealthState::Refused, Some(401));
                return refuse(VaultError::CredentialRefused, event, out);
            }
            event.status = outcome.status;
            event.outcome = match (&outcome.error, outcome.head_sent, outcome.end) {
                (_, true, "complete") => "ok".into(),
                (_, true, end) => format!("ended: {end}"),
                (Some(error), false, _) => format!("denied: {}", error.code()),
                (None, false, end) => format!("ended: {end}"),
            };
            event.detail = Some(format!(
                "{} body bytes, head after {}, {} ms in all{}",
                outcome.bytes,
                outcome.head_after.map_or("none".into(), |d| format!("{} ms", d.as_millis())),
                outcome.took.as_millis(),
                match &outcome.error {
                    Some(VaultError::UpstreamFailed(why)) => format!("; {why}"),
                    _ => String::new(),
                }
            ));
            self.audit(event);
            if let Some(state) = outcome.health {
                self.observe(record, state, outcome.status);
            }
            return match (outcome.head_sent, &outcome.error) {
                (false, Some(error)) if outcome.end != "cancelled" => error_reply(out, peer, error),
                _ => Ok(()),
            };
        }
    }

    /// The refresher of a login the vault may renew now: a kind with one, claimed (an imported
    /// login stays the host daemon's until `claim_refresh`), and not refused at this version (a
    /// dead refresh token isn't tried again until a new sign-in replaces it).
    fn renewable(&self, record: &Record) -> Option<Refresher> {
        let refresher = kinds::spec(record.kind)?.refresher?;
        if record.handover.as_ref().is_some_and(|handover| !handover.claimed) {
            return None;
        }
        let book = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if book.state_of(&record.id, record.version) == Some(HealthState::Refused) {
            return None;
        }
        Some(refresher)
    }

    /// Renews login `id` (token upkeep, R39) and returns the vault as it is afterwards. One
    /// renewal per login at a time: `seen` is the version the caller found due or refused, and
    /// if the login is at another version once this call holds the login's lock, another call
    /// renewed it (or a new sign-in replaced it) meanwhile. Then nothing is sent: the refresh
    /// token `seen` held is already spent, and the caller uses the new version.
    ///
    /// The renewed tokens are written to the vault file (the rotated refresh token with them)
    /// before this returns, so before any call uses the new access token. No token is returned
    /// or logged; the audit log names the login only.
    ///
    /// Back-off: within `RENEW_RETRY` of a failed renewal nothing is sent (an error says so).
    /// With `early` (the login is due, not because a call was refused), a login that is not
    /// expired yet and was renewed within `RENEW_EARLY_GAP` isn't renewed again.
    fn renew_login(&self, id: &str, seen: u64, why: &str, early: bool) -> Result<Arc<VaultDoc>, VaultError> {
        let lock = {
            let mut locks = self.renewing.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(locks.entry(id.to_string()).or_default())
        };
        let _one_at_a_time = lock.lock().unwrap_or_else(|e| e.into_inner());
        let doc = self.snapshot()?;
        let record = doc
            .records
            .iter()
            .find(|record| record.id == id)
            .ok_or_else(|| VaultError::UnknownSecret(format!("id {id}")))?;
        if record.version != seen {
            return Ok(Arc::clone(&doc));
        }
        let Some(refresher) = self.renewable(record) else {
            return Ok(Arc::clone(&doc));
        };
        let last = self.last_renewal.lock().unwrap_or_else(|e| e.into_inner()).get(id).copied();
        match last {
            Some((at, false)) if at.elapsed() < RENEW_RETRY => {
                return Err(VaultError::UpstreamFailed(
                    "the login's last renewal failed under a minute ago; the vault tries again after that".into(),
                ));
            }
            Some((at, true)) if early && at.elapsed() < RENEW_EARLY_GAP && record.expires_at.is_some_and(|exp| exp > crate::now_unix()) => {
                return Ok(Arc::clone(&doc));
            }
            _ => {}
        }
        let request = (refresher.call)(&record.value)?;
        let mut event = AuditEvent::named("renew", &record.name, "sending");
        event.secret_id = Some(record.id.clone());
        event.host = Some(refresher.host.to_string());
        event.detail = Some(format!("version {seen}: {why}"));
        self.record(event.clone())?; // R28
        let result = self
            .streamer
            .refresh(&request)
            .and_then(|(status, body)| (refresher.parse)(&record.value, status, &body, crate::now_unix()));
        drop(request);
        let worked = result.is_ok();
        self.last_renewal.lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string(), (std::time::Instant::now(), worked));
        match result {
            Ok((value, expires_at)) => {
                match self.with_vault(|vault| vault.renew(id, seen, Renewed { value, expires_at })) {
                    Ok((summary, backup)) => {
                        if let Err(error) = backup {
                            log(&format!("renewed {} (version {}), but its backup failed: {error}", summary.name, summary.version));
                        }
                        let mut book = self.health.lock().unwrap_or_else(|e| e.into_inner());
                        book.observe(&summary.id, summary.version, HealthState::Works, None, crate::now_rfc3339());
                        drop(book);
                        log(&format!("renewed {} (version {})", summary.name, summary.version));
                    }
                    // A new sign-in replaced it while the renewal ran: the new one stands.
                    Err(VaultError::VersionMismatch(_)) => {}
                    Err(error) => {
                        log(&format!(
                            "RENEWED {} BUT COULDN'T STORE IT ({error}): the provider has retired the stored refresh token",
                            record.name
                        ));
                        event.outcome = format!("failed: {}", error.code());
                        self.audit(event);
                        return Err(error);
                    }
                }
                self.snapshot()
            }
            Err(VaultError::CredentialRefused) => {
                event.outcome = "denied: credential_refused".into();
                event.detail = Some(format!("version {seen}: the token server refused it; sign in again"));
                self.audit(event);
                self.observe(record, HealthState::Refused, None);
                Err(VaultError::CredentialRefused)
            }
            Err(error) => {
                event.outcome = format!("failed: {}", error.code());
                if let VaultError::UpstreamFailed(detail) = &error {
                    event.detail = Some(format!("version {seen}: {detail}"));
                }
                self.audit(event);
                Err(error)
            }
        }
    }

    /// Records what a reply said about a credential, and writes the book when the state changed.
    fn observe(&self, record: &Record, state: HealthState, status: Option<u16>) {
        let mut book = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if book.observe(&record.id, record.version, state, status, crate::now_rfc3339()) {
            if let Ok(doc) = self.snapshot() {
                book.prune(&doc);
            }
            if let Err(error) = store::write_atomic(&self.paths.health_state, &book.to_json()) {
                log(&format!("couldn't write the health book: {}", error.code()));
            }
            log(&format!("credential {} is now {}", record.name, state.label()));
        }
    }

    /// Token upkeep (R39): renews every login the vault may renew (`renewable`) whose refresher
    /// says it is due. A refusal marks it refused, for the person to sign in again; any other
    /// failure is tried again at the next pass.
    fn upkeep(&self) {
        let Ok(doc) = self.snapshot() else { return };
        let now = crate::now_unix();
        for record in &doc.records {
            let Some(refresher) = self.renewable(record) else { continue };
            if !refresher.due(record.expires_at, now) {
                continue;
            }
            if let Err(error) = self.renew_login(&record.id, record.version, "due (upkeep)", true) {
                log(&format!("couldn't renew {}: {}", record.name, error.code()));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn proxy(
        &self,
        doc: &VaultDoc,
        secret: &SecretRef,
        (host, port): (Option<String>, Option<u16>),
        method: String,
        path: String,
        headers: std::collections::BTreeMap<String, String>,
        body: Option<String>,
        body_base64: Option<String>,
        peer: &Caller,
    ) -> Result<ProxyReplyOut, VaultError> {
        let logged_path: String = path.split(['?', '#']).next().unwrap_or("").chars().take(200).collect();
        let record = doc.find_ref(secret);
        let mut event = AuditEvent::named("proxy", &record.map_or_else(|| secret.label(), |r| r.name.clone()), "");
        event.secret_id = record.map(|r| r.id.clone());
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

        let Some(record) = record else {
            return Err(fail(secret.not_found(), event));
        };
        if record.kind != Kind::ApiKey {
            return Err(fail(VaultError::WrongKind, event)); // R5
        }
        let Some(rule) = &record.rule else {
            return Err(fail(VaultError::InvalidRule("this key has no rule".into()), event));
        };
        let mut event = event;
        event.host = Some(rule.host.clone());
        // Before anything else touches the request: a caller that named another destination than
        // the rule's is refused, not sent to the rule's host instead.
        if let Err(error) = rules::check_destination(rule, host.as_deref(), port) {
            if let Some(asked) = &host {
                event.host = Some(asked.chars().take(253).collect());
            }
            return Err(fail(error, event));
        }
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
