//! Encrypted backups (R18 to R21). Each backup is a standard `age` file encrypted to two keys:
//! the recovery public key (the person's kit opens it anywhere, even with the plain `age` tool)
//! and the check key, whose private half lives only inside the vault file, so the vault can
//! decrypt each backup right after writing it. Never a password.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::model::{BackupPayload, BackupStatus, Record, VAULT_FORMAT, VaultDoc};
use crate::secret::SecretValue;
use crate::store;

pub const KEEP_GENERATIONS: usize = 50;

#[derive(Serialize)]
struct BackupPayloadRef<'a> {
    format: u32,
    vault_id: &'a str,
    written_at: String,
    generation: u64,
    recovery_recipient: &'a str,
    audit_head: &'a str,
    records: &'a [Record],
}

/// A new age identity, as a `SecretValue` holding its `AGE-SECRET-KEY-1...` text.
pub fn new_identity() -> (SecretValue, String) {
    let identity = age::x25519::Identity::generate();
    let public = identity.to_public().to_string();
    let text = identity.to_string().expose_secret().to_string();
    (SecretValue::from_string(text), public)
}

/// Parses an age identity held in a `SecretValue` (the check key, or a recovery key the person
/// typed). The backup call site of `expose` in R1.
pub fn parse_identity(value: &SecretValue) -> Result<age::x25519::Identity, VaultError> {
    let text = std::str::from_utf8(value.expose()).map_err(|_| VaultError::WrongRecoveryKey)?;
    age::x25519::Identity::from_str(text.trim()).map_err(|_| VaultError::WrongRecoveryKey)
}

/// The public half of an identity, as text.
pub fn public_of(identity: &age::x25519::Identity) -> String {
    identity.to_public().to_string()
}

/// A short fingerprint of the recovery public key, for `status` and the kit.
pub fn fingerprint(recipient: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(recipient.as_bytes()));
    format!("{}-{}-{}", &digest[0..4], &digest[4..8], &digest[8..12])
}

fn file_prefix(vault_id: &str) -> String {
    format!("vault-backup-{}-", &vault_id[..vault_id.len().min(8)])
}

/// Writes a new backup of `doc`, reads it back from disk, decrypts it with the check key and
/// compares it byte for byte (R19). Then prunes old generations.
pub(crate) fn write_and_verify(doc: &VaultDoc) -> Result<BackupStatus, VaultError> {
    let dir = PathBuf::from(&doc.backup_dir);
    fs::create_dir_all(&dir).map_err(|e| VaultError::BackupFailed(format!("can't create {}: {e}", dir.display())))?;

    let written_at = crate::now_rfc3339();
    let payload = BackupPayloadRef {
        format: VAULT_FORMAT,
        vault_id: &doc.vault_id,
        written_at: written_at.clone(),
        generation: doc.generation,
        recovery_recipient: &doc.recovery_recipient,
        audit_head: &doc.audit_head,
        records: &doc.records,
    };
    let plain = Zeroizing::new(
        serde_json::to_vec(&payload).map_err(|_| VaultError::BackupFailed("encoding".into()))?,
    );

    let recovery = age::x25519::Recipient::from_str(&doc.recovery_recipient)
        .map_err(|_| VaultError::BackupFailed("the recovery public key is malformed".into()))?;
    let check = parse_identity(&doc.check_identity)
        .map_err(|_| VaultError::BackupFailed("the check key is malformed".into()))?;
    let check_public = check.to_public();
    let recipients: [&dyn age::Recipient; 2] = [&recovery, &check_public];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter())
        .map_err(|_| VaultError::BackupFailed("age refused the recipients".into()))?;
    let mut sealed = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut sealed)
        .map_err(|e| VaultError::BackupFailed(format!("age: {e}")))?;
    writer.write_all(&plain).map_err(|e| VaultError::BackupFailed(format!("age: {e}")))?;
    writer.finish().map_err(|e| VaultError::BackupFailed(format!("age: {e}")))?;

    let stamp = written_at.replace([':', '-'], "");
    let file = dir.join(format!("{}{:06}-{}.age", file_prefix(&doc.vault_id), doc.generation, stamp));
    store::write_atomic(&file, &sealed).map_err(|e| VaultError::BackupFailed(e.to_string()))?;

    // Read it back from disk and decrypt it, exactly as a restore would, then compare.
    let reread = decrypt_file(&file, &check)?;
    if reread.as_slice() != plain.as_slice() {
        return Err(VaultError::BackupMismatch);
    }
    prune(&dir, &doc.vault_id);
    Ok(BackupStatus {
        file: file.display().to_string(),
        at: written_at,
        generation: doc.generation,
        ok: true,
        detail: "written, read back and decrypted".into(),
    })
}

/// Decrypts an age file with one identity.
pub fn decrypt_file(path: &Path, identity: &dyn age::Identity) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let data = fs::read(path).map_err(|e| VaultError::BackupFailed(format!("can't read {}: {e}", path.display())))?;
    let decryptor = age::Decryptor::new_buffered(&data[..])
        .map_err(|_| VaultError::BackupFailed("not an age file".into()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity))
        .map_err(|_| VaultError::WrongRecoveryKey)?;
    let mut plain = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plain)
        .map_err(|_| VaultError::BackupFailed("the backup is damaged".into()))?;
    Ok(plain)
}

/// Decrypts and parses a backup.
pub(crate) fn open(path: &Path, identity: &dyn age::Identity) -> Result<BackupPayload, VaultError> {
    let plain = decrypt_file(path, identity)?;
    let payload: BackupPayload =
        serde_json::from_slice(&plain).map_err(|_| VaultError::BackupFailed("the backup's contents are damaged".into()))?;
    if payload.format != VAULT_FORMAT {
        return Err(VaultError::BackupFailed("unknown backup format".into()));
    }
    Ok(payload)
}

/// This vault's backups in `dir`, oldest first.
pub fn list(dir: &Path, vault_id: &str) -> Vec<PathBuf> {
    let prefix = file_prefix(vault_id);
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".age"))
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

pub fn latest(dir: &Path, vault_id: &str) -> Option<PathBuf> {
    list(dir, vault_id).pop()
}

/// Keeps the newest generations and deletes older ones, only files this vault wrote (R18).
fn prune(dir: &Path, vault_id: &str) {
    let files = list(dir, vault_id);
    if files.len() > KEEP_GENERATIONS {
        for old in &files[..files.len() - KEEP_GENERATIONS] {
            let _ = fs::remove_file(old);
        }
    }
}
