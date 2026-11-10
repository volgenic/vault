//! Key protection on platforms the vault doesn't support yet. Every call fails.

use std::path::Path;

use super::SePublic;
use crate::error::VaultError;
use crate::secret::SecretValue;

pub const DESCRIPTION: &str = "unsupported on this platform";

pub fn hardware_available() -> bool {
    false
}

pub fn create_se_key(_file: &Path) -> Result<SePublic, VaultError> {
    Err(VaultError::UnsupportedPlatform)
}

pub fn load_public(_file: &Path) -> Result<SePublic, VaultError> {
    Err(VaultError::UnsupportedPlatform)
}

pub fn wrap_and_store(_public: &SePublic, _file: &Path, _vault_key: &SecretValue) -> Result<(), VaultError> {
    Err(VaultError::UnsupportedPlatform)
}

pub fn unwrap(_se_file: &Path, _wrapped_file: &Path) -> Result<SecretValue, VaultError> {
    Err(VaultError::UnsupportedPlatform)
}
