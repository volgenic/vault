//! Key protection: how the vault key is kept between runs. This is the one module that knows
//! about the operating system's key hardware (threat model rule R30). Everything else in the
//! crate calls these functions and stays platform-neutral.
//!
//! - macOS: the vault key is wrapped to a Secure Enclave key made for this Mac only (R14).
//!   - The Secure Enclave handle lives in root's folder (`vault-root/se-key`, 0600). Only root
//!     uses it: `install-system` creates it, and the daemon unwraps the vault key while it is
//!     still root, before it drops to the vault's own account.
//!   - The wrapped vault key lives in the vault folder (`vault/vault.key`), the vault account's.
//!   - Wrapping needs only the public half, so the daemon can wrap a restored vault's new key
//!     after it has dropped root.
//!   - The vault never uses the Keychain, so no build, rebuild or update can raise a Keychain
//!     dialog.
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

/// The Secure Enclave handle, in root's folder.
pub const SE_KEY_FILE: &str = "se-key";
/// The wrapped vault key, in the vault folder.
pub const WRAPPED_KEY_FILE: &str = "vault.key";

/// Where the vault key is protected, for `vault status`.
pub const DESCRIPTION: &str = platform::DESCRIPTION;

/// The Secure Enclave key's public half: enough to wrap a vault key, never to unwrap one.
#[derive(Clone, Debug)]
pub struct SePublic(pub(crate) Vec<u8>);

/// Whether this machine has the hardware the vault needs (a Secure Enclave on macOS).
pub fn hardware_available() -> bool {
    platform::hardware_available()
}

pub fn se_key_exists(root_dir: &Path) -> bool {
    std::fs::symlink_metadata(root_dir.join(SE_KEY_FILE)).is_ok()
}

pub fn wrapped_exists(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join(WRAPPED_KEY_FILE)).is_ok()
}

/// Makes this Mac's Secure Enclave key and stores its handle in root's folder. Root only
/// (`install-system`). Fails if one is already stored.
pub fn create_se_key(root_dir: &Path) -> Result<SePublic, VaultError> {
    if se_key_exists(root_dir) {
        return Err(VaultError::AlreadyInitialized);
    }
    platform::create_se_key(&root_dir.join(SE_KEY_FILE))
}

/// The Secure Enclave key's public half (read as root, at the daemon's start).
pub fn load_public(root_dir: &Path) -> Result<SePublic, VaultError> {
    platform::load_public(&root_dir.join(SE_KEY_FILE))
}

/// Wraps a new vault key to the Secure Enclave key and stores it in the vault folder. Needs no
/// Secure Enclave access. Fails if a wrapped key is already stored.
pub fn wrap_and_store(public: &SePublic, dir: &Path, vault_key: &SecretValue) -> Result<(), VaultError> {
    if wrapped_exists(dir) {
        return Err(VaultError::AlreadyInitialized);
    }
    platform::wrap_and_store(public, &dir.join(WRAPPED_KEY_FILE), vault_key)
}

/// Unwraps the vault key with the Secure Enclave. Root only: the daemon, before it drops root.
pub fn unwrap(root_dir: &Path, dir: &Path) -> Result<SecretValue, VaultError> {
    platform::unwrap(&root_dir.join(SE_KEY_FILE), &dir.join(WRAPPED_KEY_FILE))
}

/// Removes the wrapped vault key (only `vault reset`, after the recovery key is proven). The
/// Secure Enclave key stays, so a restore on this Mac needs no root.
pub fn remove_wrapped(dir: &Path) -> Result<(), VaultError> {
    match std::fs::remove_file(dir.join(WRAPPED_KEY_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
