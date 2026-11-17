//! The audit log: one JSON line per request or command, denials included, never a value, a
//! query string or a body (R28). Each line carries the hash of the line before it, so an
//! edited or deleted line breaks the chain (R29). Past `ROTATE_AT` the log moves to
//! `audit.log.<n>` and the chain carries on in a new `audit.log`.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

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
    /// The secret's stable id, when the event is about one secret (format 2 on).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
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
    /// `reveal` only (#7666): why the caller asked for the value, in its own words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `reveal` only: who the caller says it is (an agent's handle, or `cli`). A hint like the
    /// peer's program (R23), never a permission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
    /// The id the caller gave its request (protocol 2), so a caller can match its own requests
    /// to lines here. The caller's own text: printable, at most 128 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
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


/// Past this size the log is rotated: `audit.log` is renamed `audit.log.<n>`, `n` one more than
/// the newest rotated file's (so a rotation is a single rename), and a new `audit.log` begins
/// whose first line's `prev` is the old file's head. Every file is kept: the chain runs from the
/// genesis line in `audit.log.1` (or `audit.log`, before the first rotation) through
/// `audit.log.2`, ... to `audit.log`, so it still proves every line and the head the vault file
/// records (R29). 4 MiB is about 12,000 lines.
pub const ROTATE_AT: u64 = 4 * 1024 * 1024;

/// How many of the last lines the checkpoint keeps, for `vault audit`.
const TAIL_LINES: usize = 25;
/// How many of the last changes it keeps, for `vault status`.
const RECENT_CHANGES: usize = 5;

/// The events that change the vault, shown as `vault status`'s recent changes.
pub fn is_change(event: &str) -> bool {
    matches!(
        event,
        "add" | "replace" | "set-password" | "import-plan" | "renew" | "delete" | "rename" | "restore" | "confirm-kit" | "init" | "reset"
            | "migrate"
    )
}

fn file_name(log: &Path) -> String {
    log.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "audit.log".into())
}

/// `audit.log.<n>`, beside the log.
pub fn rotated_path(log: &Path, n: u64) -> PathBuf {
    log.with_file_name(format!("{}.{n}", file_name(log)))
}

/// Every append takes this lock, not one on the log itself, because a rotation renames the log:
/// a writer waiting on the old file's lock would otherwise append to the rotated file.
fn lock_path(log: &Path) -> PathBuf {
    log.with_file_name(format!("{}.lock", file_name(log)))
}

/// The numbers of the rotated files, oldest first.
fn rotated_numbers(log: &Path) -> Result<Vec<u64>, VaultError> {
    let prefix = format!("{}.", file_name(log));
    let dir = match log.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut numbers = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        let Some(digits) = name.to_str().and_then(|n| n.strip_prefix(&prefix)) else { continue };
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = digits.parse::<u64>() {
                if n > 0 {
                    numbers.push(n);
                }
            }
        }
    }
    numbers.sort_unstable();
    Ok(numbers)
}

/// Appends an event, flushed to disk before it returns (R28: a use is on disk before it happens),
/// and returns the new head of the chain. The daemon's threads (and `vault install`, before the
/// daemon starts) append, so a lock is held while the last line is read and the new one written.
pub fn append(log: &Path, event: AuditEvent) -> Result<String, VaultError> {
    append_line(log, event, true)
}

/// Appends an event without waiting for the disk: for lines that record nothing yet to happen
/// (a refusal, or the outcome of a use whose line is already on disk). The next flushed line, or
/// the system, writes it out; a crash in between can lose it, never the chain before it.
pub fn append_unsynced(log: &Path, event: AuditEvent) -> Result<String, VaultError> {
    append_line(log, event, false)
}

fn append_line(log: &Path, event: AuditEvent, sync: bool) -> Result<String, VaultError> {
    let lock = OpenOptions::new().read(true).write(true).create(true).mode(0o600).open(lock_path(log))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(VaultError::Io("couldn't lock the audit log".into()));
    }
    let mut file = OpenOptions::new().read(true).append(true).create(true).mode(0o600).open(log)?;
    let mut prev = last_line(&mut file)?.map(|line| hash_line(&line));
    if file.metadata()?.len() >= ROTATE_AT {
        let next = rotated_numbers(log)?.last().copied().unwrap_or(0) + 1;
        let rotated = rotated_path(log, next);
        // `create_new` below would fail on a name in use; a rotated file is never overwritten.
        if rotated.exists() {
            return Err(VaultError::Io(format!("{} already exists", rotated.display())));
        }
        fs::rename(log, &rotated)?;
        if sync {
            if let Some(dir) = log.parent() {
                let _ = File::open(dir).and_then(|dir| dir.sync_all());
            }
        }
        file = OpenOptions::new().read(true).append(true).create_new(true).mode(0o600).open(log)?;
    }
    if prev.is_none() {
        // A new `audit.log` (or one a crash left empty right after a rotation): the chain carries
        // on from the newest rotated file.
        prev = rotated_head(log)?;
    }
    let prev = prev.unwrap_or_else(|| GENESIS.to_string());
    let line = AuditLine { t: crate::now_rfc3339(), event, prev };
    let text = serde_json::to_string(&line).map_err(|_| VaultError::Io("audit encoding".into()))?;
    file.write_all(format!("{text}\n").as_bytes())?;
    if sync {
        file.sync_data()?;
    }
    drop(lock);
    Ok(hash_line(&text))
}

/// The hash of the last line of the newest rotated file that has one.
fn rotated_head(log: &Path) -> Result<Option<String>, VaultError> {
    for n in rotated_numbers(log)?.into_iter().rev() {
        let mut file = File::open(rotated_path(log, n))?;
        if let Some(line) = last_line(&mut file)? {
            return Ok(Some(hash_line(&line)));
        }
    }
    Ok(None)
}

/// The last line, read from the end in growing windows (a line is a few hundred bytes; the log
/// grows by two lines per proxied call, so it isn't read whole).
fn last_line(file: &mut File) -> Result<Option<String>, VaultError> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    let mut window = 8 * 1024u64;
    loop {
        let window_now = window.min(len);
        file.seek(SeekFrom::Start(len - window_now))?;
        let mut tail = Vec::with_capacity(window_now as usize);
        file.read_to_end(&mut tail)?;
        let body = tail.strip_suffix(b"\n").unwrap_or(&tail);
        match memchr::memrchr(b'\n', body) {
            Some(index) => return Ok(Some(String::from_utf8_lossy(&body[index + 1..]).into_owned())),
            None if window_now == len => return Ok(Some(String::from_utf8_lossy(body).into_owned())),
            None => window *= 4,
        }
    }
}

/// Where a check of the chain stopped: a file, by device and inode (a rotation renames it, and
/// it is found again under its new name), how far into it, and how many lines that was.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Position {
    dev: u64,
    ino: u64,
    offset: u64,
    line: usize,
}

/// A rotated file as it was when it was checked to its end. A rotated file is never written
/// again, so any change to it (an edit, a truncation, a copy put in its place) changes its size,
/// its inode or its change time, which nobody but the kernel sets.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Stamp {
    fn of(meta: &fs::Metadata) -> Stamp {
        Stamp {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

/// How far the chain has been checked, kept in the daemon's memory so `vault status` and
/// `vault audit` check only the lines written since the last check (R29), plus one `stat` per
/// rotated file to see it is unchanged. A full check, from the first file, runs at the daemon's
/// start, for `vault audit --all`, and whenever the checkpoint can't be followed: a rotated file
/// is gone, added or changed, the checkpoint's file is gone or shorter, a new line doesn't
/// follow, or the head the vault file records isn't among the new lines.
#[derive(Clone, Debug)]
pub struct Checkpoint {
    lines: usize,
    files: usize,
    head: String,
    at: Option<Position>,
    /// The rotated files before `at`'s, as they were when they were checked to their end.
    sealed: Vec<Stamp>,
    /// The last head the vault file recorded that was found in the chain.
    found_head: Option<String>,
    tail: VecDeque<AuditLine>,
    recent: VecDeque<AuditLine>,
}

impl Default for Checkpoint {
    fn default() -> Self {
        Checkpoint {
            lines: 0,
            files: 0,
            head: GENESIS.into(),
            at: None,
            sealed: Vec::new(),
            found_head: None,
            tail: VecDeque::new(),
            recent: VecDeque::new(),
        }
    }
}

impl Checkpoint {
    /// Lines in the chain, across every file.
    pub fn lines(&self) -> usize {
        self.lines
    }

    /// Files the chain runs through (`audit.log` and the rotated ones).
    pub fn files(&self) -> usize {
        self.files
    }

    /// The last lines, oldest first.
    pub fn tail(&self) -> Vec<AuditLine> {
        self.tail.iter().cloned().collect()
    }

    /// The last changes to the vault, newest first.
    pub fn recent_changes(&self) -> impl Iterator<Item = &AuditLine> {
        self.recent.iter().rev()
    }

    fn holds(&self, recorded: Option<&str>) -> bool {
        match recorded {
            None => true,
            Some(head) => head == GENESIS || self.found_head.as_deref() == Some(head),
        }
    }
}

/// One file of the chain, opened before it is read so a rotation can't swap it underneath.
struct Segment {
    name: String,
    file: File,
    dev: u64,
    ino: u64,
}

/// The chain's files in order: the rotated ones by number, then `audit.log`. The log is opened
/// first, so a rotation in between shows up as the same file under a number, which is skipped.
fn open_segments(log: &Path) -> Result<Vec<Segment>, VaultError> {
    let current = match File::open(log) {
        Ok(file) => Some(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let current_id = match &current {
        Some(file) => {
            let meta = file.metadata()?;
            Some((meta.dev(), meta.ino()))
        }
        None => None,
    };
    let mut segments = Vec::new();
    for n in rotated_numbers(log)? {
        let path = rotated_path(log, n);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let meta = file.metadata()?;
        if Some((meta.dev(), meta.ino())) == current_id {
            continue;
        }
        segments.push(Segment { name: file_name(&path), file, dev: meta.dev(), ino: meta.ino() });
    }
    if let (Some(file), Some((dev, ino))) = (current, current_id) {
        segments.push(Segment { name: file_name(log), file, dev, ino });
    }
    Ok(segments)
}

/// Why an incremental check gave up: the checkpoint's file is gone or shorter.
struct LostPlace;

/// Checks the lines after the checkpoint, moving it to the end of the chain. `visit` sees each
/// line checked. A last line still being written (no newline yet) is left for the next check.
fn walk(
    log: &Path,
    cp: &mut Checkpoint,
    recorded: Option<&str>,
    visit: &mut dyn FnMut(AuditLine),
) -> Result<Result<(), LostPlace>, VaultError> {
    let mut segments = open_segments(log)?;
    let count = segments.len();
    let (start, mut position) = match cp.at {
        None => (0, None),
        Some(at) => match segments.iter().position(|s| s.dev == at.dev && s.ino == at.ino) {
            Some(index) => (index, Some(at)),
            None => return Ok(Err(LostPlace)),
        },
    };
    if cp.sealed.len() != start {
        return Ok(Err(LostPlace));
    }
    for (stamp, segment) in cp.sealed.iter().zip(&segments[..start]) {
        if *stamp != Stamp::of(&segment.file.metadata()?) {
            return Ok(Err(LostPlace));
        }
    }
    let mut buf = Vec::with_capacity(1024);
    for (index, segment) in segments.iter_mut().enumerate().skip(start) {
        let (mut offset, mut line_no) = match position.take() {
            Some(at) => (at.offset, at.line),
            None => (0, 0),
        };
        if segment.file.metadata()?.len() < offset {
            return Ok(Err(LostPlace));
        }
        segment.file.seek(SeekFrom::Start(offset))?;
        let last = index + 1 == count;
        let mut reader = BufReader::with_capacity(256 * 1024, &segment.file);
        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)?;
            if n == 0 || (last && buf.last() != Some(&b'\n')) {
                break;
            }
            line_no += 1;
            let broken = || VaultError::AuditChainBroken(format!("{}, line {line_no}", segment.name));
            let text = std::str::from_utf8(buf.strip_suffix(b"\n").unwrap_or(&buf)).map_err(|_| broken())?;
            let line: AuditLine = serde_json::from_str(text).map_err(|_| broken())?;
            if line.prev != cp.head {
                return Err(broken());
            }
            cp.head = hash_line(text);
            if recorded == Some(cp.head.as_str()) {
                cp.found_head = Some(cp.head.clone());
            }
            cp.lines += 1;
            offset += n as u64;
            if is_change(&line.event.event) {
                cp.recent.push_back(line.clone());
                if cp.recent.len() > RECENT_CHANGES {
                    cp.recent.pop_front();
                }
            }
            cp.tail.push_back(line.clone());
            if cp.tail.len() > TAIL_LINES {
                cp.tail.pop_front();
            }
            visit(line);
        }
        cp.at = Some(Position { dev: segment.dev, ino: segment.ino, offset, line: line_no });
        if !last {
            cp.sealed.push(Stamp::of(&segment.file.metadata()?));
        }
    }
    cp.files = count;
    Ok(Ok(()))
}

/// Checks the whole chain from its first file, and that it holds `recorded`, the head the vault
/// file records (R29). Returns a checkpoint at its end.
fn full_check(log: &Path, recorded: Option<&str>, visit: &mut dyn FnMut(AuditLine)) -> Result<Checkpoint, VaultError> {
    let mut cp = Checkpoint::default();
    match walk(log, &mut cp, recorded, visit)? {
        Ok(()) if cp.holds(recorded) => Ok(cp),
        Ok(()) => Err(VaultError::AuditHeadMissing),
        // A fresh walk starts at the first file, so it never loses its place.
        Err(LostPlace) => Err(VaultError::AuditChainBroken("a file that vanished while it was read".into())),
    }
}

/// Brings `cp` up to the end of the log, checking only the lines written since it was last
/// brought up (the cost of `vault status`), and falls back to a full check when it can't follow
/// them. On a broken chain `cp` starts over, so the next check is a full one again.
pub fn check(log: &Path, cp: &mut Checkpoint, recorded: Option<&str>) -> Result<(), VaultError> {
    if cp.at.is_some() {
        let mut next = cp.clone();
        if let Ok(Ok(())) = walk(log, &mut next, recorded, &mut |_| {}) {
            if next.holds(recorded) {
                *cp = next;
                return Ok(());
            }
        }
    }
    match full_check(log, recorded, &mut |_| {}) {
        Ok(fresh) => {
            *cp = fresh;
            Ok(())
        }
        Err(error) => {
            *cp = Checkpoint::default();
            Err(error)
        }
    }
}

/// Reads every line of every file and checks the whole chain and the recorded head (`vault audit
/// --all`). Returns the lines and a checkpoint at their end.
pub fn read_all(log: &Path, recorded: Option<&str>) -> Result<(Vec<AuditLine>, Checkpoint), VaultError> {
    let mut lines = Vec::new();
    let cp = full_check(log, recorded, &mut |line| lines.push(line))?;
    Ok((lines, cp))
}
