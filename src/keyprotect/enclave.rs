//! Wrapping the vault key with this Mac's Secure Enclave (macOS only, #7689).
//!
//! The Enclave's half is CryptoKit, in `src/macos/security.swift`: a P-256 key made in the Enclave
//! (`SecureEnclave.P256.KeyAgreement`, access `privateKeyUsage` after the first unlock, this
//! device only), an ECDH with a one-time software key, HKDF-SHA256, then AES-GCM over the 32 bytes.
//! `vault.key.se` holds the Enclave's encrypted handle to its key, the one-time public key and the
//! sealed bytes; only this Mac's Enclave can open it. The seal is bound to its vault: AES-GCM's
//! associated data is the file's magic (`VSE2`) and the vault's id, so a wrapped key put in another
//! vault's folder doesn't open. A `VSE1` file (made before the binding) is read once, and
//! `keyprotect::load` writes it again as `VSE2`.
//!
//! The Enclave sits behind a trait so a `test-stubs` build can stand one in that never touches
//! the real Enclave (no check ever makes a key in this Mac's Enclave).

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use zeroize::Zeroizing;

use super::read_own;
use crate::error::VaultError;
use crate::secret::SecretValue;

/// The largest wrapped file: the Enclave's handle is a few hundred bytes.
const MAX_WRAPPED: usize = 8192;

/// The current file format, and the one before the vault binding.
const CURRENT: &[u8; 4] = b"VSE2";
const LEGACY: &[u8; 4] = b"VSE1";
#[cfg(feature = "test-stubs")]
const STUB_CURRENT: &[u8; 4] = b"VST2";
#[cfg(feature = "test-stubs")]
const STUB_LEGACY: &[u8; 4] = b"VST1";

/// What the seal is bound to (AES-GCM's associated data): `VSE2` and the vault's 16-byte id.
fn bound_to(vault_id: &str) -> Result<Vec<u8>, String> {
    let id = hex::decode(vault_id).map_err(|_| "the vault id isn't hex".to_string())?;
    if id.len() != 16 {
        return Err("the vault id isn't 16 bytes".into());
    }
    Ok([CURRENT.as_slice(), &id].concat())
}

/// What wraps and unwraps the vault key.
trait Enclave {
    /// Why it can't wrap here, or nothing when it can.
    fn ready(&self) -> Result<(), String>;
    /// Wraps `key`, bound to `aad`.
    fn wrap(&self, key: &SecretValue, aad: &[u8]) -> Result<Vec<u8>, String>;
    /// Unwraps a file `wrap` wrote with the same `aad` (`VSE1` for a legacy file).
    fn unwrap(&self, wrapped: &[u8], aad: &[u8]) -> Result<SecretValue, String>;
}

/// This Mac's Secure Enclave, through CryptoKit. Not in a `test-stubs` build.
#[cfg(not(feature = "test-stubs"))]
struct Real;

#[cfg(not(feature = "test-stubs"))]
unsafe extern "C" {
    fn vault_se_available() -> i32;
    fn vault_se_wrap(
        key: *const u8,
        key_len: usize,
        aad: *const u8,
        aad_len: usize,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> i32;
    fn vault_se_unwrap(wrapped: *const u8, wrapped_len: usize, aad: *const u8, aad_len: usize, out: *mut u8) -> i32;
}

/// The Swift side's results (`security.swift`).
#[cfg(not(feature = "test-stubs"))]
fn result(code: i32) -> Result<(), String> {
    match code {
        0 => Ok(()),
        1 => Err("this Mac has no Secure Enclave".into()),
        4 => Err("the wrapped key file isn't one the vault wrote".into()),
        _ => Err("the Secure Enclave refused it (a key made on another Mac or for another vault, or the Enclave was reset)".into()),
    }
}

#[cfg(not(feature = "test-stubs"))]
impl Enclave for Real {
    fn ready(&self) -> Result<(), String> {
        if unsafe { vault_se_available() } == 1 { Ok(()) } else { Err("this Mac has no Secure Enclave".into()) }
    }

    fn wrap(&self, key: &SecretValue, aad: &[u8]) -> Result<Vec<u8>, String> {
        // The seal's call site of `expose` in R1: the key goes to the Enclave's seal, nowhere else.
        let key = key.expose();
        let mut out = vec![0u8; MAX_WRAPPED];
        let mut len = 0usize;
        result(unsafe {
            vault_se_wrap(key.as_ptr(), key.len(), aad.as_ptr(), aad.len(), out.as_mut_ptr(), out.len(), &mut len)
        })?;
        out.truncate(len);
        Ok(out)
    }

    fn unwrap(&self, wrapped: &[u8], aad: &[u8]) -> Result<SecretValue, String> {
        // Into a fixed buffer, wiped on drop (R1).
        let mut key = Zeroizing::new([0u8; 32]);
        result(unsafe { vault_se_unwrap(wrapped.as_ptr(), wrapped.len(), aad.as_ptr(), aad.len(), key.as_mut_ptr()) })?;
        Ok(SecretValue::from_vec(key.to_vec()))
    }
}

/// A `test-stubs` build's stand-in, never a release: wraps with XChaCha20-Poly1305 under the
/// 32-byte file `VAULT_TEST_ENCLAVE_KEY` names, the "Mac's" key, bound to the same associated data
/// as the real one. Another file is "another Mac". `VST1` is its legacy format (no binding).
#[cfg(feature = "test-stubs")]
struct Stub;

#[cfg(feature = "test-stubs")]
impl Stub {
    fn key(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let path = std::env::var_os("VAULT_TEST_ENCLAVE_KEY").ok_or("this Mac has no Secure Enclave (a test-stubs build without VAULT_TEST_ENCLAVE_KEY)")?;
        let key = Zeroizing::new(std::fs::read(path).map_err(|e| format!("the stand-in Enclave's key: {e}"))?);
        if key.len() != 32 {
            return Err("the stand-in Enclave's key isn't 32 bytes".into());
        }
        Ok(key)
    }
}

#[cfg(feature = "test-stubs")]
impl Enclave for Stub {
    fn ready(&self) -> Result<(), String> {
        self.key().map(|_| ())
    }

    fn wrap(&self, key: &SecretValue, aad: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&self.key()?).map_err(|e| e.to_string())?;
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
        // A legacy file, for evidence of the rewrite: `VAULT_TEST_ENCLAVE_LEGACY=1` writes `VST1`.
        if std::env::var("VAULT_TEST_ENCLAVE_LEGACY").as_deref() == Ok("1") {
            let sealed = cipher.encrypt(&nonce.into(), key.expose()).map_err(|_| "the stand-in Enclave failed".to_string())?;
            return Ok([STUB_LEGACY.as_slice(), &nonce, &sealed].concat());
        }
        let sealed = cipher
            .encrypt(&nonce.into(), Payload { msg: key.expose(), aad })
            .map_err(|_| "the stand-in Enclave failed".to_string())?;
        Ok([STUB_CURRENT.as_slice(), &nonce, &sealed].concat())
    }

    fn unwrap(&self, wrapped: &[u8], aad: &[u8]) -> Result<SecretValue, String> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        if wrapped.len() < 28 || (&wrapped[..4] != STUB_CURRENT && &wrapped[..4] != STUB_LEGACY) {
            return Err("the wrapped key file isn't one the vault wrote".into());
        }
        let aad: &[u8] = if &wrapped[..4] == STUB_LEGACY { &[] } else { aad };
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&self.key()?).map_err(|e| e.to_string())?;
        let nonce: [u8; 24] = wrapped[4..28].try_into().map_err(|_| "short".to_string())?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(&nonce.into(), Payload { msg: &wrapped[28..], aad })
                .map_err(|_| "the Secure Enclave refused it (a key made on another Mac or for another vault, or the Enclave was reset)".to_string())?,
        );
        Ok(SecretValue::from_vec(plain.to_vec()))
    }
}

#[cfg(not(feature = "test-stubs"))]
fn enclave() -> impl Enclave {
    Real
}

#[cfg(feature = "test-stubs")]
fn enclave() -> impl Enclave {
    Stub
}

pub(super) fn ready() -> Result<(), String> {
    enclave().ready()
}

/// Reads a wrapped key file (`fstat`-checked, `O_NOFOLLOW`) and unwraps it, bound to vault
/// `vault_id`. Says whether the file is a legacy one (`VSE1`), to write again.
pub fn unseal(path: &Path, vault_id: &str) -> Result<(SecretValue, bool), VaultError> {
    let wrapped = read_own(path)?;
    if wrapped.len() > MAX_WRAPPED {
        return Err(VaultError::SealedKey("the wrapped key file is too large to be one".into()));
    }
    let legacy = wrapped.starts_with(LEGACY) || cfg!(feature = "test-stubs") && wrapped.starts_with(b"VST1");
    let aad = if legacy { LEGACY.to_vec() } else { bound_to(vault_id).map_err(VaultError::SealedKey)? };
    let key = enclave().unwrap(&wrapped, &aad).map_err(VaultError::SealedKey)?;
    if key.len() != 32 {
        return Err(VaultError::SealedKey("the unwrapped key isn't 32 bytes".into()));
    }
    Ok((key, legacy))
}

/// Wraps `key` with a new Enclave key, bound to vault `vault_id`, into the new file `temp`
/// (mode 0600, `O_EXCL`). The caller checks the round trip and puts it in place.
pub fn seal(temp: &Path, vault_id: &str, key: &SecretValue) -> Result<(), String> {
    let enclave = enclave();
    enclave.ready()?;
    let wrapped = enclave.wrap(key, &bound_to(vault_id)?)?;
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(temp).map_err(|e| e.to_string())?;
    file.write_all(&wrapped).and_then(|()| file.sync_all()).map_err(|e| e.to_string())
}
