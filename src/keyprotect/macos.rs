//! macOS key protection, through the Swift shim in `macos.swift` (built by build.rs). Secure
//! Enclave only; no Keychain, so no Keychain dialog for any build.

use std::path::Path;

use zeroize::Zeroize;

use crate::error::VaultError;
use crate::secret::SecretValue;
use crate::store;

pub const DESCRIPTION: &str = "Secure Enclave key for this Mac only; wrapped vault key in key.se (no Keychain)";

unsafe extern "C" {
    fn vkp_se_available() -> i32;
    fn vkp_se_create(
        handle_out: *mut u8,
        handle_cap: usize,
        handle_len: *mut usize,
        pub_out: *mut u8,
        pub_cap: usize,
        pub_len: *mut usize,
    ) -> i32;
    fn vkp_wrap(
        public: *const u8,
        public_len: usize,
        plain: *const u8,
        plain_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> i32;
    fn vkp_se_unwrap(
        handle: *const u8,
        handle_len: usize,
        wrapped: *const u8,
        wrapped_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> i32;
}

const RECORD_MAGIC: &[u8; 4] = b"VKP2";
const BUFFER: usize = 4096;

fn check(code: i32) -> Result<(), VaultError> {
    match code {
        0 => Ok(()),
        2 => Err(VaultError::SecureEnclave),
        _ => Err(VaultError::KeyProtection),
    }
}

pub fn hardware_available() -> bool {
    unsafe { vkp_se_available() == 1 }
}

pub fn store_new(file: &Path, vault_key: &SecretValue) -> Result<(), VaultError> {
    let mut handle = vec![0u8; BUFFER];
    let mut public = vec![0u8; 128];
    let (mut handle_len, mut public_len) = (0usize, 0usize);
    check(unsafe {
        vkp_se_create(
            handle.as_mut_ptr(),
            handle.len(),
            &mut handle_len,
            public.as_mut_ptr(),
            public.len(),
            &mut public_len,
        )
    })?;
    handle.truncate(handle_len);
    public.truncate(public_len);

    let mut wrapped = vec![0u8; BUFFER];
    let mut wrapped_len = 0usize;
    let key = vault_key.expose(); // R1: wrapping the vault key
    check(unsafe {
        vkp_wrap(
            public.as_ptr(),
            public.len(),
            key.as_ptr(),
            key.len(),
            wrapped.as_mut_ptr(),
            wrapped.len(),
            &mut wrapped_len,
        )
    })?;
    wrapped.truncate(wrapped_len);

    let handle_len = u16::try_from(handle.len()).map_err(|_| VaultError::KeyProtection)?;
    let public_len = u8::try_from(public.len()).map_err(|_| VaultError::KeyProtection)?;
    let mut record = Vec::with_capacity(8 + handle.len() + public.len() + wrapped.len());
    record.extend_from_slice(RECORD_MAGIC);
    record.extend_from_slice(&handle_len.to_be_bytes());
    record.extend_from_slice(&handle);
    record.push(public_len);
    record.extend_from_slice(&public);
    record.extend_from_slice(&wrapped);
    let result = store::write_atomic(file, &record);
    record.zeroize();
    handle.zeroize();
    result
}

pub fn load(file: &Path) -> Result<SecretValue, VaultError> {
    let mut record = match std::fs::read(file) {
        Ok(record) => record,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(VaultError::NotInitialized),
        Err(error) => return Err(error.into()),
    };
    let result = unwrap_record(&record);
    record.zeroize();
    result
}

fn unwrap_record(record: &[u8]) -> Result<SecretValue, VaultError> {
    let bad = || VaultError::KeyProtection;
    let rest = record.strip_prefix(RECORD_MAGIC.as_slice()).ok_or_else(bad)?;
    let (len_bytes, rest) = rest.split_at_checked(2).ok_or_else(bad)?;
    let handle_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
    let (handle, rest) = rest.split_at_checked(handle_len).ok_or_else(bad)?;
    let (public_len, rest) = rest.split_first().ok_or_else(bad)?;
    let (_public, wrapped) = rest.split_at_checked(*public_len as usize).ok_or_else(bad)?;

    let mut out = vec![0u8; 256];
    let mut out_len = 0usize;
    let code = unsafe {
        vkp_se_unwrap(
            handle.as_ptr(),
            handle.len(),
            wrapped.as_ptr(),
            wrapped.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        )
    };
    if let Err(error) = check(code) {
        out.zeroize();
        return Err(error);
    }
    out.truncate(out_len);
    Ok(SecretValue::from_vec(out))
}
