//! Where the vault keeps its files, and the encrypted vault file itself (R13).
//!
//! Everything is the owner's own, under a base folder in his home (home from the user database,
//! never `$HOME`, R15):
//!
//! | Folder           | Mode | Holds                                                    |
//! |------------------|------|----------------------------------------------------------|
//! | `bin/`           | 0700 | the installed program                                    |
//! | `vault/`         | 0700 | vault file, vault key (0600), audit log, restore point   |
//! | `vault-backups/` | 0700 | backups (ciphertext)                                     |
//!
//! - **macOS:** the base is `~/Library/Application Support/Volgenic/`, the socket is in its
//!   `socket/` folder (0700), and the daemon is a LaunchAgent in the owner's login
//!   (`~/Library/LaunchAgents/`).
//! - **Linux:** the base is `~/.local/share/volgenic/`, and the daemon is a systemd user service
//!   (`~/.config/systemd/user/volgenic-vault.service`) that starts at boot through lingering. The
//!   socket is in `/run/user/<uid>/volgenic/` (0700), the folder systemd makes for the service
//!   (`RuntimeDirectory=volgenic`, which is `$XDG_RUNTIME_DIR/volgenic`). The path is worked out
//!   from the user ID, not read from `$XDG_RUNTIME_DIR` (R15). A machine with no
//!   `/run/user/<uid>` (no systemd, such as a container) uses the base's `socket/` folder.

use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::model::{self, VAULT_FORMAT, VaultDoc};
use crate::secret::SecretValue;

/// The file's magic: `VGVAULT` and the format's number in the last byte, bound into the
/// encryption as associated data together with the vault id (R13).
const MAGIC_PREFIX: &[u8; 7] = b"VGVAULT";
const MAGIC_LEN: usize = 8;
const ID_LEN: usize = 16;
const NONCE_LEN: usize = 24;

fn magic(format: u32) -> [u8; MAGIC_LEN] {
    let mut magic = [0u8; MAGIC_LEN];
    magic[..7].copy_from_slice(MAGIC_PREFIX);
    magic[7] = format as u8;
    magic
}

#[cfg(target_os = "macos")]
pub const DAEMON_LABEL: &str = "com.volgenic.vault";
#[cfg(not(target_os = "macos"))]
pub const DAEMON_LABEL: &str = "volgenic-vault.service";
pub const MIRROR_LABEL: &str = "com.volgenic.vault.mirror";

/// Every path the vault uses.
#[derive(Clone, Debug)]
pub struct Paths {
    pub base: PathBuf,
    pub bin_dir: PathBuf,
    pub program: PathBuf,
    pub dir: PathBuf,
    pub vault_file: PathBuf,
    pub audit_log: PathBuf,
    pub restore_point: PathBuf,
    pub restore_point_info: PathBuf,
    pub mirror_state: PathBuf,
    /// What upstream replies said about each credential (`health`): ids, states and times only.
    pub health_state: PathBuf,
    pub local_backups: PathBuf,
    pub socket_dir: PathBuf,
    pub socket: PathBuf,
    /// The daemon's job: the LaunchAgent's plist on macOS, the systemd user unit on Linux.
    pub service_file: PathBuf,
    pub log_dir: PathBuf,
    pub daemon_log: PathBuf,
}

impl Paths {
    /// The running user's vault.
    pub fn current() -> Paths {
        let uid = unsafe { libc::getuid() };
        let home = account_by_uid(uid).map(|a| a.home).unwrap_or_else(|| PathBuf::from("/var/empty"));
        Paths::for_user(uid, &home)
    }

    #[cfg(target_os = "macos")]
    pub fn for_user(_uid: u32, home: &Path) -> Paths {
        let base = home.join("Library/Application Support/Volgenic");
        let socket_dir = base.join("socket");
        let log_dir = home.join("Library/Logs/Volgenic");
        let service_file = home.join(format!("Library/LaunchAgents/{DAEMON_LABEL}.plist"));
        Paths::assemble(base, socket_dir, log_dir, service_file)
    }

    #[cfg(not(target_os = "macos"))]
    pub fn for_user(uid: u32, home: &Path) -> Paths {
        let base = home.join(".local/share/volgenic");
        let socket_dir = match runtime_dir(uid) {
            Some(runtime) => runtime.join("volgenic"),
            None => base.join("socket"),
        };
        let log_dir = home.join(".local/state/volgenic");
        let service_file = home.join(format!(".config/systemd/user/{DAEMON_LABEL}"));
        Paths::assemble(base, socket_dir, log_dir, service_file)
    }

    fn assemble(base: PathBuf, socket_dir: PathBuf, log_dir: PathBuf, service_file: PathBuf) -> Paths {
        let bin_dir = base.join("bin");
        let dir = base.join("vault");
        Paths {
            program: bin_dir.join("vault"),
            vault_file: dir.join("vault.bin"),
            audit_log: dir.join("audit.log"),
            restore_point: dir.join("restore-point.age"),
            restore_point_info: dir.join("restore-point.json"),
            mirror_state: dir.join("mirror.json"),
            health_state: dir.join("health.json"),
            local_backups: base.join("vault-backups"),
            socket: socket_dir.join("vault.sock"),
            daemon_log: log_dir.join("vault.log"),
            service_file,
            log_dir,
            bin_dir,
            dir,
            socket_dir,
            base,
        }
    }
}

/// The user's runtime folder, `/run/user/<uid>`, when it exists and is the user's own: systemd's
/// login manager makes it at the first login, or at boot for a user with lingering on. It is
/// what `$XDG_RUNTIME_DIR` names, worked out from the user ID instead of read from the
/// environment (R15).
#[cfg(not(target_os = "macos"))]
pub fn runtime_dir(uid: u32) -> Option<PathBuf> {
    let dir = PathBuf::from(format!("/run/user/{uid}"));
    let meta = fs::symlink_metadata(&dir).ok()?;
    (meta.is_dir() && meta.uid() == uid).then_some(dir)
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

    /// The suggested mirror folder: in iCloud Drive on macOS. Only `vault mirror` ever opens it
    /// (R32).
    #[cfg(target_os = "macos")]
    pub fn default_mirror_dir(&self) -> PathBuf {
        self.home.join("Library/Mobile Documents/com~apple~CloudDocs/Volgenic Vault Backups")
    }

    /// The suggested mirror folder on Linux, where the mirror isn't installable yet: a folder in
    /// the home folder, for the person to point at another disk or a synced folder later.
    #[cfg(not(target_os = "macos"))]
    pub fn default_mirror_dir(&self) -> PathBuf {
        self.home.join("Volgenic Vault Backups")
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

/// A fresh random id, 16 bytes as hex: a vault id, or a secret's id.
pub fn new_random_id() -> Result<String, VaultError> {
    let mut id = [0u8; ID_LEN];
    getrandom::getrandom(&mut id).map_err(|_| VaultError::Random)?;
    Ok(hex::encode(id))
}

/// A fresh random vault id, as hex.
pub fn new_vault_id() -> Result<String, VaultError> {
    new_random_id()
}

/// Encrypts and writes the vault file atomically, mode 0600 (R13), always in the current format.
/// The vault-file call site of `expose` in R1.
pub(crate) fn save(paths: &Paths, key: &SecretValue, doc: &VaultDoc) -> Result<(), VaultError> {
    let id = hex::decode(&doc.vault_id).map_err(|_| VaultError::VaultFileCorrupt)?;
    if id.len() != ID_LEN || doc.format != VAULT_FORMAT {
        return Err(VaultError::VaultFileCorrupt);
    }
    let magic = magic(VAULT_FORMAT);
    let plain = Zeroizing::new(serde_json::to_vec(doc).map_err(|_| VaultError::VaultFileCorrupt)?);
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| VaultError::Random)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| VaultError::KeyProtection)?;
    let aad = [magic.as_slice(), &id].concat();
    let sealed = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: &aad })
        .map_err(|_| VaultError::VaultFileCorrupt)?;
    let mut out = Vec::with_capacity(MAGIC_LEN + ID_LEN + NONCE_LEN + sealed.len());
    out.extend_from_slice(&magic);
    out.extend_from_slice(&id);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    write_atomic(&paths.vault_file, &out)
}

/// The vault id in the vault file's header, read without the key: what the sealed key is bound
/// to (`keyprotect`).
pub fn file_vault_id(paths: &Paths) -> Result<String, VaultError> {
    let mut header = [0u8; MAGIC_LEN + ID_LEN];
    File::open(&paths.vault_file)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|error| VaultError::VaultFileUnreadable(error.to_string()))?;
    if &header[..MAGIC_PREFIX.len()] != MAGIC_PREFIX {
        return Err(VaultError::VaultFileCorrupt);
    }
    Ok(hex::encode(&header[MAGIC_LEN..]))
}

/// Reads and decrypts the vault file. Any change to the file, including its id or its format
/// byte, fails here. Reads every format this build knows (1 to 4); an older document comes
/// back as it is, and the caller migrates it (`model::migrate`, `model::ensure_intake`) and writes
/// it back in the current format.
/// A file from a newer build is refused with `NewerFormat`, never guessed at.
pub(crate) fn load(paths: &Paths, key: &SecretValue) -> Result<VaultDoc, VaultError> {
    let mut data = Vec::new();
    File::open(&paths.vault_file)
        .and_then(|mut file| file.read_to_end(&mut data))
        .map_err(|error| VaultError::VaultFileUnreadable(error.to_string()))?;
    let header = MAGIC_LEN + ID_LEN + NONCE_LEN;
    if data.len() <= header || &data[..MAGIC_PREFIX.len()] != MAGIC_PREFIX {
        return Err(VaultError::VaultFileCorrupt);
    }
    let format = u32::from(data[MAGIC_LEN - 1]);
    if format > VAULT_FORMAT {
        return Err(VaultError::NewerFormat(format));
    }
    if !model::READABLE_FORMATS.contains(&format) {
        return Err(VaultError::VaultFileCorrupt);
    }
    let id = &data[MAGIC_LEN..MAGIC_LEN + ID_LEN];
    let nonce = &data[MAGIC_LEN + ID_LEN..header];
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| VaultError::KeyProtection)?;
    let aad = [&data[..MAGIC_LEN], id].concat();
    let plain = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: &data[header..], aad: &aad })
            .map_err(|_| VaultError::VaultFileCorrupt)?,
    );
    let doc: VaultDoc = serde_json::from_slice(&plain).map_err(|_| VaultError::VaultFileCorrupt)?;
    if doc.vault_id != hex::encode(id) || doc.format != format {
        return Err(VaultError::VaultFileCorrupt);
    }
    model::check_ids(&doc.records, format)?;
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
