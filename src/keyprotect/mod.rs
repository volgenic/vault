//! Key protection, kept simple on purpose: the vault key is 32 random bytes in a mode-0600 file
//! next to the vault file, in the owner's own folder. No Secure Enclave and no Keychain, so
//! nothing the vault does can ever raise a dialog. The bar is "better than plaintext secrets on
//! a server": the vault file is encrypted, and only the owner's account can read either file.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::error::VaultError;
use crate::secret::SecretValue;

/// The vault key, in the vault folder.
pub const KEY_FILE: &str = "vault.key";

/// Where the vault key is kept, for `vault status`.
pub const DESCRIPTION: &str = "vault key in a mode-600 file next to the vault file (no Secure Enclave, no Keychain)";

pub fn key_exists(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(KEY_FILE)).is_ok()
}

/// Writes a new vault key, mode 0600. Fails if one is already stored. The key-file call site
/// of `expose` in R1.
pub fn store_new(dir: &Path, key: &SecretValue) -> Result<(), VaultError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join(KEY_FILE))
        .map_err(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { VaultError::AlreadyInitialized } else { e.into() })?;
    file.write_all(key.expose())?;
    file.sync_all()?;
    Ok(())
}

/// Reads the vault key. Refuses a key file anyone else could read.
pub fn load(dir: &Path) -> Result<SecretValue, VaultError> {
    let path = dir.join(KEY_FILE);
    let meta = fs::symlink_metadata(&path).map_err(|_| VaultError::KeyProtection)?;
    if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::getuid() } {
        return Err(VaultError::UnsafeVaultFolder(format!("{} must be a 0600 file of yours", path.display())));
    }
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(32));
    fs::File::open(&path)?.read_to_end(&mut buf)?;
    if buf.len() != 32 {
        return Err(VaultError::KeyProtection);
    }
    Ok(SecretValue::from_vec(buf.to_vec()))
}

/// Removes the vault key (only `vault reset`, after the recovery key is proven).
pub fn remove(dir: &Path) -> Result<(), VaultError> {
    match fs::remove_file(dir.join(KEY_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
