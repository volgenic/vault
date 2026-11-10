//! `vault mirror`: run by the owner's LaunchAgent `com.volgenic.vault.mirror` whenever the local
//! backup folder changes, and hourly. It copies each backup to the mirror folder (iCloud Drive
//! by default), checks every copy byte for byte by SHA-256, keeps the last 50 of the current
//! vault there, and reports to the daemon (R32).
//!
//! It holds no key and decrypts nothing. It is the only program that opens the mirror folder, so
//! macOS's one file-access dialog for iCloud Drive names the vault, comes once, and is
//! remembered for the program's path and signature.

use std::path::{Path, PathBuf};

use serde_json::json;

use crate::backup;
use crate::client;
use crate::error::VaultError;
use crate::store::{self, Paths};

struct Outcome {
    copied: usize,
    already_there: usize,
    newest: Option<PathBuf>,
}

fn copy_and_check(source: &Path, target: &Path) -> Result<bool, VaultError> {
    let want = backup::sha256_file(source)?;
    if target.is_file() && backup::sha256_file(target).ok().as_deref() == Some(want.as_str()) {
        return Ok(false);
    }
    let bytes = std::fs::read(source)
        .map_err(|e| VaultError::BackupFailed(format!("can't read {}: {e}", source.display())))?;
    store::write_atomic(target, &bytes)
        .map_err(|e| VaultError::BackupFailed(format!("can't write {}: {e}", target.display())))?;
    let got = backup::sha256_file(target)?;
    if got != want {
        return Err(VaultError::BackupFailed(format!(
            "the copy {} differs from the original after writing",
            target.display()
        )));
    }
    Ok(true)
}

fn mirror_once(local: &Path, mirror: &Path, vault_id: &str) -> Result<Outcome, VaultError> {
    backup::ensure_backup_dir(mirror)?;
    let mut outcome = Outcome { copied: 0, already_there: 0, newest: None };
    for source in backup::list_all(local) {
        let Some(name) = source.file_name() else { continue };
        let target = mirror.join(name);
        if copy_and_check(&source, &target)? {
            outcome.copied += 1;
        } else {
            outcome.already_there += 1;
        }
    }
    backup::prune(mirror, vault_id);
    outcome.newest = backup::latest(mirror, vault_id);
    Ok(outcome)
}

pub fn run() -> Result<(), VaultError> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(VaultError::Io("the mirror runs as the vault's owner, never as root".into()));
    }
    let paths = Paths::current();
    let plan = client::mirror_plan(&paths)?;
    let started = crate::now_rfc3339();
    let result = mirror_once(Path::new(&plan.local_dir), Path::new(&plan.mirror_dir), &plan.vault_id);
    let report = match &result {
        Ok(outcome) => json!({
            "ok": true,
            "newest_file": outcome.newest.as_ref().map(|p| p.display().to_string()),
            "newest_generation": outcome.newest.as_deref().and_then(backup::generation_of),
            "copied": outcome.copied,
            "already_there": outcome.already_there,
            "detail": "",
        }),
        Err(error) => json!({ "ok": false, "detail": error.to_string() }),
    };
    eprintln!(
        "{started} vault mirror: {} -> {}: {}",
        plan.local_dir,
        plan.mirror_dir,
        match &result {
            Ok(o) => format!("ok, copied {}, already there {}", o.copied, o.already_there),
            Err(e) => format!("FAILED: {e}"),
        }
    );
    client::mirror_report(&paths, report)?;
    result.map(|_| ())
}
