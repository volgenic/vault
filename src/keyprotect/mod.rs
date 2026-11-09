//! Key protection: where the vault key is kept between runs. This is the one module that knows
//! about the operating system's key storage (threat model rule R30). Everything else in the
//! crate calls these four functions and stays platform-neutral.
//!
//! - macOS: the vault key is wrapped by a Secure Enclave key, and the wrapped copy plus the
//!   Secure Enclave handle live in the login-Keychain item `com.volgenic.vault` (R14).
//! - Linux: planned (systemd credentials, TPM where present). Until then every call fails.

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

/// Where the vault key is protected, for `vault status`.
pub const DESCRIPTION: &str = platform::DESCRIPTION;

/// Whether this machine has the hardware the vault needs (a Secure Enclave on macOS).
pub fn hardware_available() -> bool {
    platform::hardware_available()
}

/// Whether a protected vault key is already stored. Reads no secret data.
pub fn exists() -> Result<bool, VaultError> {
    platform::exists()
}

/// Protects and stores a new vault key. Fails if one is already stored.
pub fn store_new(vault_key: &SecretValue) -> Result<(), VaultError> {
    platform::store_new(vault_key)
}

/// Loads the vault key.
pub fn load() -> Result<SecretValue, VaultError> {
    platform::load()
}

/// Removes the stored vault key (only `vault reset`, after the recovery key is proven).
pub fn remove() -> Result<(), VaultError> {
    platform::remove()
}
