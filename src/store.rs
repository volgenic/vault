//! Where the vault keeps its files, and the encrypted vault file itself (R3, R13 to R15, R22).
//!
//! Every path is fixed, under `/Library/Application Support/Volgenic/`, which only root can
//! change. No flag or environment variable moves anything (R15).
//!
//! | Folder         | Owner            | Mode | Holds                                              |
//! |----------------|------------------|------|----------------------------------------------------|
//! | `bin/`         | root             | 0755 | the program                                        |
//! | `vault-root/`  | root             | 0700 | the Secure Enclave handle, `system.json`           |
//! | `vault/`       | `_volgenicvault` | 0700 | vault file, wrapped key, audit log, restore point  |
//! | `vault-backups/` | `_volgenicvault` | 0755 | backups (ciphertext, 0644, read by the mirror)   |
//! | `socket/`      | `_volgenicvault` | 0755 | the socket, 0666                                   |

use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::model::{VAULT_FORMAT, VaultDoc};
use crate::secret::SecretValue;

const MAGIC: &[u8; 8] = b"VGVAULT\x01";
const ID_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// The vault's own macOS account: a role account (name starts with `_`, ID in 450-499).
pub const ROLE_USER: &str = "_volgenicvault";
/// Role accounts take user and group IDs in this range (`sysadminctl -h`: "Role accounts
/// require name starting with _ and UID in 450-499 range").
pub const ROLE_ID_RANGE: std::ops::RangeInclusive<u32> = 450..=499;

pub const DAEMON_LABEL: &str = "com.volgenic.vault";
pub const MIRROR_LABEL: &str = "com.volgenic.vault.mirror";

/// Every system path the vault uses.
#[derive(Clone, Debug)]
pub struct Paths {
    pub base: PathBuf,
    pub bin_dir: PathBuf,
    pub program: PathBuf,
    pub root_dir: PathBuf,
    pub system_file: PathBuf,
    pub dir: PathBuf,
    pub vault_file: PathBuf,
    pub audit_log: PathBuf,
    pub restore_point: PathBuf,
    pub restore_point_info: PathBuf,
    pub mirror_state: PathBuf,
    pub local_backups: PathBuf,
    pub socket_dir: PathBuf,
    pub socket: PathBuf,
    pub daemon_plist: PathBuf,
    pub log_dir: PathBuf,
    pub daemon_log: PathBuf,
}

impl Paths {
    pub fn system() -> Paths {
        let base = PathBuf::from("/Library/Application Support/Volgenic");
        let bin_dir = base.join("bin");
        let root_dir = base.join("vault-root");
        let dir = base.join("vault");
        let socket_dir = base.join("socket");
        let log_dir = PathBuf::from("/Library/Logs/Volgenic");
        Paths {
            program: bin_dir.join("vault"),
            system_file: root_dir.join("system.json"),
            vault_file: dir.join("vault.bin"),
            audit_log: dir.join("audit.log"),
            restore_point: dir.join("restore-point.age"),
            restore_point_info: dir.join("restore-point.json"),
            mirror_state: dir.join("mirror.json"),
            local_backups: base.join("vault-backups"),
            socket: socket_dir.join("vault.sock"),
            daemon_plist: PathBuf::from(format!("/Library/LaunchDaemons/{DAEMON_LABEL}.plist")),
            daemon_log: log_dir.join("vault.log"),
            log_dir,
            bin_dir,
            root_dir,
            dir,
            socket_dir,
            base,
        }
    }
}

/// The paths that belong to the person who owns the vault.
#[derive(Clone, Debug)]
pub struct OwnerPaths {
    pub uid: u32,
    pub name: String,
    pub home: PathBuf,
    pub mirror_plist: PathBuf,
    pub mirror_log: PathBuf,
    pub default_kit: PathBuf,
}

impl OwnerPaths {
    /// From the user database, never `$HOME` (R15).
    pub fn for_uid(uid: u32) -> Result<OwnerPaths, VaultError> {
        let account = account_by_uid(uid).ok_or_else(|| VaultError::Io(format!("no user with ID {uid}")))?;
        let home = account.home.clone();
        Ok(OwnerPaths {
            uid,
            name: account.name,
            mirror_plist: home.join(format!("Library/LaunchAgents/{MIRROR_LABEL}.plist")),
            mirror_log: home.join("Library/Logs/Volgenic/vault-mirror.log"),
            default_kit: home.join("Volgenic Vault Recovery Kit.txt"),
            home,
        })
    }

    /// The suggested mirror folder, in iCloud Drive. Only `vault mirror` ever opens it (R32).
    pub fn icloud_backups(&self) -> PathBuf {
        self.home.join("Library/Mobile Documents/com~apple~CloudDocs/Volgenic Vault Backups")
    }

    /// `~/x` in something the person typed, against this user's home.
    pub fn expand(&self, text: &str) -> PathBuf {
        match text.strip_prefix("~/") {
            Some(rest) => self.home.join(rest),
            None if text == "~" => self.home.clone(),
            None => PathBuf::from(text),
        }
    }
}

/// An account from the user database.
#[derive(Clone, Debug)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub shell: String,
}

unsafe fn account_from(pw: *const libc::passwd) -> Option<Account> {
    if pw.is_null() {
        return None;
    }
    let text = |p: *const libc::c_char| {
        if p.is_null() { String::new() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() }
    };
    unsafe {
        Some(Account {
            name: text((*pw).pw_name),
            uid: (*pw).pw_uid,
            gid: (*pw).pw_gid,
            home: PathBuf::from(text((*pw).pw_dir)),
            shell: text((*pw).pw_shell),
        })
    }
}

pub fn account_by_uid(uid: u32) -> Option<Account> {
    unsafe { account_from(libc::getpwuid(uid)) }
}

pub fn account_by_name(name: &str) -> Option<Account> {
    let name = CString::new(name).ok()?;
    unsafe { account_from(libc::getpwnam(name.as_ptr())) }
}

/// The vault's role account, if it exists.
pub fn role_account() -> Option<Account> {
    account_by_name(ROLE_USER)
}

/// What `install-system` records in root's folder: who owns the vault, and its account.
/// Only root can write it (R15).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SystemConfig {
    pub owner_uid: u32,
    pub role_uid: u32,
    pub role_gid: u32,
    pub installed_at: String,
    pub installed_version: String,
}

pub fn read_system_config(paths: &Paths) -> Result<SystemConfig, VaultError> {
    check_dir(&paths.root_dir, 0, 0o077)?;
    let meta = fs::symlink_metadata(&paths.system_file).map_err(|_| VaultError::NotInstalled)?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(VaultError::UnsafeVaultFolder(format!("{} isn't root's", paths.system_file.display())));
    }
    let bytes = fs::read(&paths.system_file)?;
    serde_json::from_slice(&bytes).map_err(|_| VaultError::Io(format!("{} is damaged", paths.system_file.display())))
}

pub fn write_system_config(paths: &Paths, config: &SystemConfig) -> Result<(), VaultError> {
    let bytes = serde_json::to_vec_pretty(config).map_err(|_| VaultError::Io("system.json encoding".into()))?;
    write_atomic(&paths.system_file, &bytes)
}

/// Checks a folder: a real folder (not a symbolic link), owned by `uid`, with none of the
/// `forbidden` mode bits set (R22).
pub fn check_dir(dir: &Path, uid: u32, forbidden: u32) -> Result<(), VaultError> {
    let meta = fs::symlink_metadata(dir)
        .map_err(|e| VaultError::UnsafeVaultFolder(format!("{}: {e}", dir.display())))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(VaultError::UnsafeVaultFolder(format!("{} isn't a plain folder", dir.display())));
    }
    if meta.uid() != uid {
        return Err(VaultError::UnsafeVaultFolder(format!(
            "{} belongs to user ID {}, not {uid}",
            dir.display(),
            meta.uid()
        )));
    }
    if meta.mode() & forbidden != 0 {
        return Err(VaultError::UnsafeVaultFolder(format!(
            "{} has mode {:o}",
            dir.display(),
            meta.mode() & 0o7777
        )));
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

/// Encrypts and writes the vault file atomically, mode 0600 (R13).
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

/// Writes `bytes` to `path` through a temporary file, flushed, then renamed into place; mode 0600.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    write_atomic_mode(path, bytes, 0o600)
}

/// `write_atomic` with a chosen mode (backups are 0644, so the owner's mirror can copy them).
pub fn write_atomic_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<(), VaultError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().ok_or_else(|| VaultError::Io("no parent folder".into()))?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let temp = dir.join(format!(".{name}.tmp-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
    {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)?;
        file.write_all(bytes)?;
        if mode != 0o600 {
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
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
