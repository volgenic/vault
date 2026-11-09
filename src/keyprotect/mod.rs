//! Key protection: how the vault key is kept between runs. This is the one module that knows
//! about the operating system's key hardware (threat model rule R30). Everything else in the
//! crate calls these functions and stays platform-neutral.
//!
//! - macOS: the vault key is wrapped by a Secure Enclave key made for this Mac only. The Secure
//!   Enclave handle and the wrapped key live in `key.se` in the vault folder (R14). The vault
//!   never uses the Keychain, so no build, rebuild or update can raise a Keychain dialog.
//! - Linux: planned (systemd credentials, TPM where present). Until then every call fails.

use std::path::Path;

use crate::error::VaultError;
use crate::secret::SecretValue;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

#[cfg(not(target_os = "macos"))]
mod unsupported;
#[cfg(not(target_os = "macos"))]
use unsupported as platform;

/// The file in the vault folder that holds the protected vault key.
pub const KEY_FILE: &str = "key.se";

/// Where the vault key is protected, for `vault status`.
pub const DESCRIPTION: &str = platform::DESCRIPTION;

/// Whether this machine has the hardware the vault needs (a Secure Enclave on macOS).
pub fn hardware_available() -> bool {
    platform::hardware_available()
}

/// Whether a protected vault key is already stored in `dir`.
pub fn exists(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join(KEY_FILE)).is_ok()
}

/// Protects a new vault key and stores it in `dir`. Fails if one is already stored.
pub fn store_new(dir: &Path, vault_key: &SecretValue) -> Result<(), VaultError> {
    if exists(dir) {
        return Err(VaultError::AlreadyInitialized);
    }
    platform::store_new(&dir.join(KEY_FILE), vault_key)
}

/// Loads the vault key from `dir`.
pub fn load(dir: &Path) -> Result<SecretValue, VaultError> {
    platform::load(&dir.join(KEY_FILE))
}

/// Removes the stored vault key (only `vault reset`, after the recovery key is proven).
pub fn remove(dir: &Path) -> Result<(), VaultError> {
    match std::fs::remove_file(dir.join(KEY_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
