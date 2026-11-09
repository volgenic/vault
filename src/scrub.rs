//! Looks for a key in an API's reply before the agent sees it (R12). A debug or "who am I"
//! endpoint that echoes request headers would otherwise hand the key straight back.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use crate::secret::SecretValue;

/// The forms of the key the vault searches for: as is, base64 (standard and URL-safe, with
/// and without padding), percent-encoded and hex (both cases).
/// This and `build_header` in proxy.rs are the proxy's call sites of `expose` in R1.
pub(crate) fn needles(key: &SecretValue) -> Vec<Zeroizing<Vec<u8>>> {
    let raw = key.expose();
    let mut forms: Vec<Zeroizing<Vec<u8>>> = vec![Zeroizing::new(raw.to_vec())];
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        forms.push(Zeroizing::new(engine.encode(raw).into_bytes()));
    }
    forms.push(Zeroizing::new(hex::encode(raw).into_bytes()));
    forms.push(Zeroizing::new(hex::encode_upper(raw).into_bytes()));
    for upper in [true, false] {
        let mut encoded = Vec::with_capacity(raw.len() * 3);
        for &b in raw {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                encoded.push(b);
            } else if upper {
                encoded.extend_from_slice(format!("%{b:02X}").as_bytes());
            } else {
                encoded.extend_from_slice(format!("%{b:02x}").as_bytes());
            }
        }
        forms.push(Zeroizing::new(encoded));
    }
    forms.retain(|form| !form.is_empty());
    forms.dedup_by(|a, b| a.as_slice() == b.as_slice());
    forms
}

/// Whether `haystack` contains any of the forms.
pub(crate) fn contains_any(haystack: &[u8], forms: &[Zeroizing<Vec<u8>>]) -> bool {
    forms.iter().any(|form| memchr::memmem::find(haystack, form).is_some())
}
