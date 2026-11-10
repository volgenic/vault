//! The audit log: one JSON line per request or command, denials included, never a value, a
//! query string or a body (R28). Each line carries the hash of the line before it, so an
//! edited or deleted line breaks the chain (R29).

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::VaultError;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One audit entry. Fields hold names, hosts, paths and outcomes only.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AuditEvent {
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The path only; the query is never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// The caller hint (R23): process number and program path. Never a permission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_pid: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_program: Option<String>,
}

impl AuditEvent {
    pub fn new(event: &str, outcome: &str) -> Self {
        AuditEvent { event: event.into(), outcome: outcome.into(), ..Default::default() }
    }

    pub fn named(event: &str, name: &str, outcome: &str) -> Self {
        AuditEvent { name: Some(name.into()), ..AuditEvent::new(event, outcome) }
    }
}

/// A line as written: time, the event, and the previous line's hash.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditLine {
    pub t: String,
    #[serde(flatten)]
    pub event: AuditEvent,
    pub prev: String,
}

pub fn hash_line(line: &str) -> String {
    hex::encode(Sha256::digest(line.as_bytes()))
}

/// Appends an event and returns the new head of the chain. The daemon's threads (and
/// `install-system`, before the daemon starts) append,
/// so the file is locked while the last line is read and the new one written.
pub fn append(log: &Path, event: AuditEvent) -> Result<String, VaultError> {
    let mut file = OpenOptions::new().read(true).append(true).create(true).mode(0o600).open(log)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(VaultError::Io("couldn't lock the audit log".into()));
    }
    let prev = match last_line(&mut file)? {
        Some(line) => hash_line(&line),
        None => GENESIS.to_string(),
    };
    let line = AuditLine { t: crate::now_rfc3339(), event, prev };
    let text = serde_json::to_string(&line).map_err(|_| VaultError::Io("audit encoding".into()))?;
    file.write_all(format!("{text}\n").as_bytes())?;
    file.sync_data()?;
    Ok(hash_line(&text))
    // The lock is released when `file` closes.
}

fn last_line(file: &mut File) -> Result<Option<String>, VaultError> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    let window = len.min(256 * 1024);
    file.seek(SeekFrom::Start(len - window))?;
    let mut tail = Vec::with_capacity(window as usize);
    file.read_to_end(&mut tail)?;
    let text = String::from_utf8_lossy(&tail);
    Ok(text.trim_end_matches('\n').rsplit('\n').next().map(str::to_string))
}

/// Reads the whole log and checks the chain. Returns the lines and the head.
pub fn read_and_verify(log: &Path) -> Result<(Vec<AuditLine>, String), VaultError> {
    let file = match File::open(log) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), GENESIS.into())),
        Err(error) => return Err(error.into()),
    };
    let mut lines = Vec::new();
    let mut head = GENESIS.to_string();
    for (index, text) in BufReader::new(file).lines().enumerate() {
        let text = text?;
        let line: AuditLine = serde_json::from_str(&text).map_err(|_| VaultError::AuditChainBroken(index + 1))?;
        if line.prev != head {
            return Err(VaultError::AuditChainBroken(index + 1));
        }
        head = hash_line(&text);
        lines.push(line);
    }
    Ok((lines, head))
}

/// Whether a head recorded in the vault file appears in the chain (true for the genesis head).
pub fn chain_contains(log: &Path, recorded_head: &str) -> Result<bool, VaultError> {
    if recorded_head == GENESIS {
        return Ok(true);
    }
    let file = match File::open(log) {
        Ok(file) => file,
        Err(_) => return Ok(false),
    };
    for text in BufReader::new(file).lines() {
        if hash_line(&text?) == recorded_head {
            return Ok(true);
        }
    }
    Ok(false)
}
