//! The command-line tool's side of the socket, for the two requests it makes of `serve`:
//! writing a backup and checking the newest one (R32). Only `serve` touches the backup folder,
//! so the one macOS file-access permission it may need (iCloud Drive, say) belongs to the vault
//! itself, granted once, and never to Terminal or to whatever program started an agent.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde::de::DeserializeOwned;

use crate::error::VaultError;
use crate::protocol::{BackupCheck, BackupReply, VerifyBackupReply};
use crate::store::Paths;

/// Long enough for a person to answer a macOS permission dialog that holds up `serve`'s first
/// write to the backup folder.
const BACKUP_WAIT: Duration = Duration::from_secs(300);

fn call<T: DeserializeOwned>(paths: &Paths, request: &str) -> Result<T, VaultError> {
    let mut stream = UnixStream::connect(&paths.socket).map_err(|_| {
        VaultError::BackupFailed(
            "`vault serve` isn't running, and only it writes backups; run `vault install-agent`".into(),
        )
    })?;
    stream.set_read_timeout(Some(BACKUP_WAIT))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(request.as_bytes())?;
    stream.write_all(b"\n")?;
    let mut line = Vec::new();
    BufReader::new(&stream).read_until(b'\n', &mut line)?;
    if let Ok(reply) = serde_json::from_slice::<T>(&line) {
        return Ok(reply);
    }
    let error: serde_json::Value = serde_json::from_slice(&line)
        .map_err(|_| VaultError::BackupFailed("`vault serve` sent an unreadable reply".into()))?;
    let message = error.get("message").and_then(|m| m.as_str()).unwrap_or("no reason given");
    Err(VaultError::BackupFailed(format!("`vault serve`: {message}")))
}

/// Asks `serve` to write (if not yet written) and verify the backup of the current generation.
pub fn request_backup(paths: &Paths) -> Result<crate::model::BackupStatus, VaultError> {
    call::<BackupReply>(paths, r#"{"op":"backup"}"#).map(|reply| reply.backup)
}

/// Asks `serve` to decrypt the newest backup with the check key and compare it with the vault.
pub fn request_verify(paths: &Paths) -> Result<BackupCheck, VaultError> {
    call::<VerifyBackupReply>(paths, r#"{"op":"verify-backup"}"#).map(|reply| reply.check)
}

/// Waits up to `wait` for `serve` to answer on the socket.
pub fn wait_for_serve(paths: &Paths, wait: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < wait {
        if let Ok(mut stream) = UnixStream::connect(&paths.socket) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            if stream.write_all(b"{\"op\":\"list\"}\n").is_ok() {
                let mut line = Vec::new();
                if BufReader::new(&stream).read_until(b'\n', &mut line).is_ok_and(|n| n > 0) {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}
