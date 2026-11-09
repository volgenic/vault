//! Placeholder for platforms the vault doesn't support yet. Linux is planned.

use std::path::Path;

use crate::error::VaultError;
use crate::secret::SecretValue;

pub const DESCRIPTION: &str = "unsupported on this platform (Linux is planned)";

pub fn hardware_available() -> bool {
    false
}

pub fn store_new(_file: &Path, _vault_key: &SecretValue) -> Result<(), VaultError> {
    Err(VaultError::UnsupportedPlatform)
}

pub fn load(_file: &Path) -> Result<SecretValue, VaultError> {
    Err(VaultError::UnsupportedPlatform)
}
