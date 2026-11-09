//! `vault serve`: the background part agents talk to, over a socket only this user can reach
//! (R22 to R25). It never writes the vault file; changes come from the command-line tool, and
//! `serve` reloads the vault file when it changes. It is the only program that touches the
//! backup folder (R32): the command-line tool asks it to write and check backups.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::audit::{self, AuditEvent};
use crate::error::VaultError;
use crate::model::{Kind, VaultDoc};
use crate::platform::{self, Peer};
use crate::backup;
use crate::protocol::{self, BackupReply, ErrorReply, ListReply, ProxyReplyOut, Request, TotpReply, VerifyBackupReply};
use crate::proxy::{self, ProxyRequest};
use crate::secret::SecretValue;
use crate::store::{self, Paths};
use crate::vault::{self, Vault};

const MAX_CONNECTIONS: usize = 16;

struct Snapshot {
    fingerprint: Option<(u64, i64, i64)>,
    doc: Arc<VaultDoc>,
}

struct Server {
    paths: Paths,
    key: SecretValue,
    snapshot: RwLock<Snapshot>,
    client: reqwest::blocking::Client,
    active: AtomicUsize,
    backups: Mutex<()>,
}

pub fn serve(paths: &Paths) -> Result<(), VaultError> {
    if platform::auto_login_on() {
        return Err(VaultError::AutoLoginOn); // R31
    }
    let opened = Vault::open(paths)?;
    let Vault { key, doc, .. } = opened;
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
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;

    let server = Arc::new(Server {
        paths: paths.clone(),
        key,
        snapshot: RwLock::new(Snapshot { fingerprint: store::fingerprint(paths), doc: Arc::new(doc) }),
        client,
        active: AtomicUsize::new(0),
        backups: Mutex::new(()),
    });
    let mut event = AuditEvent::new("serve", "started");
    event.detail = Some(format!("pid {}, socket {}", std::process::id(), paths.socket.display()));
    audit::append(&paths.audit_log, event)?;
    eprintln!("vault: serving on {}", paths.socket.display());

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

impl Server {
    fn current(&self) -> Result<Arc<VaultDoc>, VaultError> {
        let now = store::fingerprint(&self.paths);
        {
            let snapshot = self.snapshot.read().map_err(|_| VaultError::Busy)?;
            if snapshot.fingerprint == now {
                return Ok(Arc::clone(&snapshot.doc));
            }
        }
        let doc = Arc::new(store::load(&self.paths, &self.key)?);
        let mut snapshot = self.snapshot.write().map_err(|_| VaultError::Busy)?;
        *snapshot = Snapshot { fingerprint: now, doc: Arc::clone(&doc) };
        Ok(doc)
    }

    fn audit(&self, event: AuditEvent) {
        if let Err(error) = audit::append(&self.paths.audit_log, event) {
            eprintln!("vault: couldn't write the audit log: {}", error.code());
        }
    }

    fn handle(&self, mut stream: UnixStream) {
        // R22: only this macOS user. R23: the caller's pid and program are a hint, not a pass.
        let Some(peer) = platform::peer_of(stream.as_raw_fd()) else { return };
        if peer.uid != unsafe { libc::getuid() } {
            let mut event = AuditEvent::new("connect", "denied: another macOS user");
            event.detail = Some(format!("uid {}", peer.uid));
            self.audit(with_peer(event, &peer));
            return;
        }
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

        let mut line = Vec::new();
        let read = BufReader::new((&stream).take(protocol::MAX_REQUEST_LINE as u64 + 1)).read_until(b'\n', &mut line);
        if read.is_err() || line.len() > protocol::MAX_REQUEST_LINE {
            let error = VaultError::BadRequest("unreadable or over 2 MiB".into());
            self.audit(with_peer(AuditEvent::new("request", &format!("denied: {}", error.code())), &peer));
            let _ = reply(&mut stream, &ErrorReply::from(&error));
            return;
        }
        let request: Request = match serde_json::from_slice(&line) {
            Ok(request) => request,
            Err(_) => {
                let error = VaultError::BadRequest("not a valid request; see the protocol in the README".into());
                self.audit(with_peer(AuditEvent::new("request", "denied: bad_request"), &peer));
                let _ = reply(&mut stream, &ErrorReply::from(&error));
                return;
            }
        };
        let doc = match self.current() {
            Ok(doc) => doc,
            Err(error) => {
                self.audit(with_peer(AuditEvent::new("request", &format!("failed: {}", error.code())), &peer));
                let _ = reply(&mut stream, &ErrorReply::from(&error));
                // The vault file was replaced (a reset and restore makes a new vault key) or
                // removed. Exit; launchd starts `serve` again, which loads the current key.
                if matches!(error, VaultError::VaultFileCorrupt | VaultError::VaultFileUnreadable(_)) {
                    eprintln!("vault: the vault file changed under serve ({}); exiting so launchd restarts it", error.code());
                    std::process::exit(75);
                }
                return;
            }
        };
        let _ = match request {
            Request::List => {
                self.audit(with_peer(AuditEvent::new("list", "ok"), &peer));
                reply(&mut stream, &ListReply { ok: true, secrets: doc.summaries() })
            }
            Request::Totp { name } => match vault::totp_code(&doc, &name) {
                Ok(code) => {
                    self.audit(with_peer(AuditEvent::named("totp", &name, "ok"), &peer));
                    reply(&mut stream, &TotpReply { ok: true, name, code: code.code, seconds_left: code.seconds_left })
                }
                Err(error) => {
                    self.audit(with_peer(AuditEvent::named("totp", &name, &format!("denied: {}", error.code())), &peer));
                    reply(&mut stream, &ErrorReply::from(&error))
                }
            },
            Request::Backup => {
                let _one_at_a_time = self.backups.lock().unwrap_or_else(|e| e.into_inner());
                match backup::write_and_verify(&doc) {
                    Ok(status) => {
                        let mut event = AuditEvent::new("backup-request", "ok");
                        event.detail = Some(format!("generation {}: {}", status.generation, status.detail));
                        self.audit(with_peer(event, &peer));
                        reply(&mut stream, &BackupReply { ok: true, backup: status })
                    }
                    Err(error) => {
                        let mut event = AuditEvent::new("backup-request", &format!("failed: {}", error.code()));
                        event.detail = Some(error.to_string());
                        self.audit(with_peer(event, &peer));
                        reply(&mut stream, &ErrorReply::from(&error))
                    }
                }
            }
            Request::VerifyBackup => {
                let _one_at_a_time = self.backups.lock().unwrap_or_else(|e| e.into_inner());
                match backup::check_newest(&doc) {
                    Ok(check) => {
                        let outcome = if check.matches_vault { "ok" } else { "differs from vault" };
                        let mut event = AuditEvent::new("verify-backup", outcome);
                        event.detail = Some(format!("{} (generation {})", check.file, check.generation));
                        self.audit(with_peer(event, &peer));
                        reply(&mut stream, &VerifyBackupReply { ok: true, check })
                    }
                    Err(error) => {
                        self.audit(with_peer(AuditEvent::new("verify-backup", &format!("failed: {}", error.code())), &peer));
                        reply(&mut stream, &ErrorReply::from(&error))
                    }
                }
            }
            Request::Proxy { name, method, path, headers, body, body_base64 } => {
                let outcome = self.proxy(&doc, &name, method, path, headers, body, body_base64, &peer);
                match outcome {
                    Ok(out) => reply(&mut stream, &out),
                    Err(error) => reply(&mut stream, &ErrorReply::from(&error)),
                }
            }
        };
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
