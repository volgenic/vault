//! The vault's library. Decisions live here as functions over plain values; the Secure Enclave
//! code stays behind one small key-protection module (`keyprotect`), so the rest can build on
//! Linux later. The vault never uses the Keychain, so it never raises a Keychain dialog.
//!
//! The rules this code follows are numbered on the threat model page,
//! https://volgenic.com/pages/4171d207-a31e-4d38-b659-60ceed9ee5fd, and cited as R1, R2, ...

pub mod audit;
pub mod backup;
pub mod error;
pub mod keyprotect;
pub mod model;
pub mod platform;
pub mod protocol;
pub mod proxy;
pub mod rules;
pub mod scrub;
pub mod secret;
pub mod server;
pub mod store;
pub mod totp;
pub mod vault;

/// The vault's version, from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Now, as RFC 3339 in UTC, to the second.
pub fn now_rfc3339() -> String {
    let now = time::OffsetDateTime::now_utc().replace_nanosecond(0).unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    now.format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| "unknown".into())
}

/// Now, in Unix seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
