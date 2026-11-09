//! Placeholder for platforms the vault doesn't support yet. Linux is planned.

use crate::error::VaultError;
use crate::secret::SecretValue;

pub const DESCRIPTION: &str = "unsupported on this platform (Linux is planned)";

pub fn hardware_available() -> bool {
    false
}

pub fn exists() -> Result<bool, VaultError> {
    Err(VaultError::UnsupportedPlatform)
}

pub fn store_new(_vault_key: &SecretValue) -> Result<(), VaultError> {
    Err(VaultError::UnsupportedPlatform)
}

pub fn load() -> Result<SecretValue, VaultError> {
    Err(VaultError::UnsupportedPlatform)
}

pub fn remove() -> Result<(), VaultError> {
    Err(VaultError::UnsupportedPlatform)
}
