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

    /// A new random password for a sign-up (`generate_login`, #7663): `length` characters from
    /// letters, digits and ten punctuation marks most sites accept. It has at least one character
    /// of each kind, because many sites demand that. Every character is uniform over the alphabet
    /// (rejection sampling of random bytes). It is made straight into wiped buffers and exists
    /// nowhere but the vault, its backups and the page a fill types it into.
    pub fn random_password(length: usize) -> Result<Self, crate::error::VaultError> {
        use zeroize::Zeroizing;
        const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const DIGITS: &[u8] = b"0123456789";
        const SYMBOLS: &[u8] = b"!#%+-.=?@_";
        let mut alphabet = Vec::with_capacity(72);
        for set in [LOWER, UPPER, DIGITS, SYMBOLS] {
            alphabet.extend_from_slice(set);
        }
        // The largest multiple of the alphabet's size that fits in a byte: bytes at or above it
        // are thrown away, so no character is likelier than another.
        let limit = 256 - 256 % alphabet.len();
        let mut password = Zeroizing::new(Vec::with_capacity(length));
        let mut random = Zeroizing::new([0u8; 64]);
        for _ in 0..1000 {
            password.clear();
            while password.len() < length {
                getrandom::getrandom(&mut random[..]).map_err(|_| crate::error::VaultError::Random)?;
                for &byte in random.iter() {
                    if (byte as usize) < limit && password.len() < length {
                        password.push(alphabet[byte as usize % alphabet.len()]);
                    }
                }
            }
            let has = |set: &[u8]| password.iter().any(|c| set.contains(c));
            if has(LOWER) && has(UPPER) && has(DIGITS) && has(SYMBOLS) {
                return Ok(SecretValue::from_vec(std::mem::take(&mut *password)));
            }
        }
        Err(crate::error::VaultError::Random)
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

/// A byte buffer that never leaves an unwiped copy of its contents behind (R1). When it must
/// grow it copies into a new allocation and wipes the old one, instead of letting `Vec`
/// reallocate; it wipes itself when dropped. Used for request lines and secret values read off
/// the socket.
pub(crate) struct WipingBuf {
    bytes: Vec<u8>,
}

impl WipingBuf {
    pub fn with_capacity(capacity: usize) -> Self {
        WipingBuf { bytes: Vec::with_capacity(capacity.max(16)) }
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        let needed = self.bytes.len() + data.len();
        if needed > self.bytes.capacity() {
            let mut grown = Vec::with_capacity(needed.max(self.bytes.capacity() * 2));
            grown.extend_from_slice(&self.bytes);
            self.bytes.zeroize(); // wipes the whole old allocation, spare capacity included
            self.bytes = grown;
        }
        self.bytes.extend_from_slice(data);
    }

    pub fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn into_secret(mut self) -> SecretValue {
        SecretValue::from_vec(std::mem::take(&mut self.bytes))
    }
}

impl Drop for WipingBuf {
    fn drop(&mut self) {
        self.bytes.zeroize();
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
