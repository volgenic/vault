//! Where the vault keeps its files, and the encrypted vault file itself (R13, R15, R22).
//!
//! The folder is fixed: `~/Library/Application Support/Volgenic/vault/`, with the home folder
//! taken from the user database, not `$HOME`. No flag or environment variable moves it (R15).

use std::ffi::CStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::model::{VAULT_FORMAT, VaultDoc};
use crate::secret::SecretValue;

const MAGIC: &[u8; 8] = b"VGVAULT\x01";
const ID_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// Every path the vault uses.
#[derive(Clone, Debug)]
pub struct Paths {
    pub home: PathBuf,
    pub dir: PathBuf,
    pub vault_file: PathBuf,
    pub audit_log: PathBuf,
    pub socket: PathBuf,
    pub lock_file: PathBuf,
    pub local_backups: PathBuf,
    pub log_file: PathBuf,
    pub launch_agent: PathBuf,
}

impl Paths {
    pub fn for_current_user() -> Result<Paths, VaultError> {
        let home = home_from_user_database()?;
        let dir = home.join("Library/Application Support/Volgenic/vault");
        Ok(Paths {
            vault_file: dir.join("vault.bin"),
            audit_log: dir.join("audit.log"),
            socket: dir.join("vault.sock"),
            lock_file: dir.join("vault.lock"),
            local_backups: dir.join("backups"),
            log_file: home.join("Library/Logs/Volgenic/vault.log"),
            launch_agent: home.join("Library/LaunchAgents/com.volgenic.vault.plist"),
            dir,
            home,
        })
    }

    /// iCloud Drive's folder for vault backups, if iCloud Drive is set up on this Mac.
    pub fn icloud_backups(&self) -> Option<PathBuf> {
        let drive = self.home.join("Library/Mobile Documents/com~apple~CloudDocs");
        drive.is_dir().then(|| drive.join("Volgenic Vault Backups"))
    }
}

fn home_from_user_database() -> Result<PathBuf, VaultError> {
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() || (*pw).pw_dir.is_null() {
            return Err(VaultError::Io("can't find the home folder in the user database".into()));
        }
        let dir = CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
        Ok(PathBuf::from(dir))
    }
}

/// Makes the folder if needed, then checks it: a real folder (not a symbolic link), owned by
/// this user, closed to everyone else (R22).
pub fn ensure_private_dir(dir: &Path) -> Result<(), VaultError> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    check_private_dir(dir)
}

pub fn check_private_dir(dir: &Path) -> Result<(), VaultError> {
    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(VaultError::UnsafeVaultFolder(format!("{} isn't a plain folder", dir.display())));
    }
    if meta.uid() != unsafe { libc::getuid() } {
        return Err(VaultError::UnsafeVaultFolder(format!("{} belongs to another user", dir.display())));
    }
    if meta.mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn vault_exists(paths: &Paths) -> bool {
    fs::symlink_metadata(&paths.vault_file).is_ok()
}

/// A fresh random vault id, as hex.
pub fn new_vault_id() -> Result<String, VaultError> {
    let mut id = [0u8; ID_LEN];
    getrandom::getrandom(&mut id).map_err(|_| VaultError::Random)?;
    Ok(hex::encode(id))
}

/// Encrypts and writes the vault file atomically, readable only by the user (R13).
/// The vault-file call site of `expose` in R1.
pub(crate) fn save(paths: &Paths, key: &SecretValue, doc: &VaultDoc) -> Result<(), VaultError> {
    let id = hex::decode(&doc.vault_id).map_err(|_| VaultError::VaultFileCorrupt)?;
    if id.len() != ID_LEN || doc.format != VAULT_FORMAT {
        return Err(VaultError::VaultFileCorrupt);
    }
    let plain = Zeroizing::new(serde_json::to_vec(doc).map_err(|_| VaultError::VaultFileCorrupt)?);
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| VaultError::Random)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| VaultError::KeyProtection)?;
    let aad = [MAGIC.as_slice(), &id].concat();
    let sealed = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: &aad })
        .map_err(|_| VaultError::VaultFileCorrupt)?;
    let mut out = Vec::with_capacity(MAGIC.len() + ID_LEN + NONCE_LEN + sealed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&id);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    write_atomic(&paths.vault_file, &out)
}

/// Reads and decrypts the vault file. Any change to the file, including its id, fails here.
pub(crate) fn load(paths: &Paths, key: &SecretValue) -> Result<VaultDoc, VaultError> {
    let mut data = Vec::new();
    File::open(&paths.vault_file)
        .and_then(|mut file| file.read_to_end(&mut data))
        .map_err(|error| VaultError::VaultFileUnreadable(error.to_string()))?;
    let header = MAGIC.len() + ID_LEN + NONCE_LEN;
    if data.len() <= header || &data[..MAGIC.len()] != MAGIC {
        return Err(VaultError::VaultFileCorrupt);
    }
    let id = &data[MAGIC.len()..MAGIC.len() + ID_LEN];
    let nonce = &data[MAGIC.len() + ID_LEN..header];
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| VaultError::KeyProtection)?;
    let aad = [MAGIC.as_slice(), id].concat();
    let plain = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: &data[header..], aad: &aad })
            .map_err(|_| VaultError::VaultFileCorrupt)?,
    );
    let doc: VaultDoc = serde_json::from_slice(&plain).map_err(|_| VaultError::VaultFileCorrupt)?;
    if doc.vault_id != hex::encode(id) || doc.format != VAULT_FORMAT {
        return Err(VaultError::VaultFileCorrupt);
    }
    Ok(doc)
}

/// The vault file's size and modification time, so `serve` notices changes made by the CLI.
pub fn fingerprint(paths: &Paths) -> Option<(u64, i64, i64)> {
    fs::metadata(&paths.vault_file).ok().map(|meta| (meta.len(), meta.mtime(), meta.mtime_nsec()))
}

/// Writes `bytes` to `path` through a temporary file, flushed, then renamed into place.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let dir = path.parent().ok_or_else(|| VaultError::Io("no parent folder".into()))?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let temp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    if let Ok(folder) = File::open(dir) {
        let _ = folder.sync_all();
    }
    Ok(())
}

/// An exclusive lock on the vault, held while a command changes it.
pub struct ChangeLock {
    _file: File,
}

pub fn lock_for_change(paths: &Paths) -> Result<ChangeLock, VaultError> {
    use std::os::fd::AsRawFd;
    let file = OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(&paths.lock_file)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(VaultError::Io("couldn't lock the vault".into()));
    }
    Ok(ChangeLock { _file: file })
}
