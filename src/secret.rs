//! `SecretValue`: the one type that holds a secret value (threat model rule R1).
//!
//! It can't be printed (`Debug` shows `[secret]`, and there is no `Display`), cloned or
//! serialized (no `Serialize`, so no reply type can carry one: R4). It is locked against
//! swapping where macOS allows and wiped when dropped. Reading its bytes takes `expose`, which
//! is private to this library: the command-line executable can't call it at all.

use std::fmt;

use zeroize::Zeroize;

pub struct SecretValue {
    bytes: Box<[u8]>,
}

impl SecretValue {
    /// Takes ownership of `bytes` and wipes the vector's whole buffer after copying.
    pub fn from_vec(mut bytes: Vec<u8>) -> Self {
        let boxed: Box<[u8]> = bytes.as_slice().into();
        bytes.zeroize();
        let secret = SecretValue { bytes: boxed };
        secret.lock();
        secret
    }

    /// Takes ownership of `text` (for instance from a hidden prompt) and wipes it.
    pub fn from_string(mut text: String) -> Self {
        let secret = SecretValue::from_vec(text.as_bytes().to_vec());
        text.zeroize();
        secret
    }

    /// Fresh random bytes from the operating system.
    pub fn random(len: usize) -> Result<Self, crate::error::VaultError> {
        let mut bytes = vec![0u8; len];
        getrandom::getrandom(&mut bytes).map_err(|_| crate::error::VaultError::Random)?;
        Ok(SecretValue::from_vec(bytes))
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The secret's bytes. Every call site is listed in R1; a new one needs a reason in its PR.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// Constant-time equality, for checking a backup against the vault.
    pub(crate) fn same_as(&self, other: &SecretValue) -> bool {
        if self.bytes.len() != other.bytes.len() {
            return false;
        }
        self.bytes.iter().zip(other.bytes.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    }

    fn lock(&self) {
        if !self.bytes.is_empty() {
            // Best effort: macOS limits how much a process may lock. Swap is encrypted anyway.
            unsafe {
                libc::mlock(self.bytes.as_ptr().cast(), self.bytes.len());
            }
        }
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.bytes.zeroize();
        if !self.bytes.is_empty() {
            unsafe {
                libc::munlock(self.bytes.as_ptr().cast(), self.bytes.len());
            }
        }
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[secret]")
    }
}
