//! The vault's library. Decisions live here as functions over plain values. The vault key is
//! sealed to the machine when it can be (`keyprotect`): wrapped by the Secure Enclave on a Mac, by
//! the TPM through systemd-creds on Linux, else a mode-0600 file next to the vault file. No
//! Keychain item, and the only dialog is the person's own Touch ID for their sensitive acts
//! (`presence`, R46).
//!
//! The vault runs as the owner: a daemon (`server`) started by a LaunchAgent in his login on
//! macOS or by a systemd user service at boot on Linux, a command-line tool that only talks to
//! it (`client`), the installer (`install`) and the optional backup mirror (`mirror`, macOS).
//! What differs between the two systems sits behind `cfg` in `platform`, `store` (paths),
//! `keyprotect`, `install` and the proxy's TLS setup.
//!
//! The rules this code follows are numbered on the threat model page,
//! https://volgenic.com/pages/4171d207-a31e-4d38-b659-60ceed9ee5fd, and cited as R1, R2, ...

// The stand-ins (`test-stubs`: a fake Secure Enclave and Touch ID) never go into a release.
#[cfg(all(feature = "test-stubs", not(debug_assertions)))]
compile_error!("the `test-stubs` feature is for local evidence only and can't be built in release mode");

pub mod audit;
pub mod backup;
pub mod client;
pub mod details;
pub mod error;
pub mod evm;
pub mod fill;
pub mod health;
pub mod install;
pub mod intake;
pub mod keyprotect;
pub mod kinds;
pub mod lease;
pub mod logins;
pub mod mirror;
pub mod model;
pub mod platform;
pub mod presence;
pub mod protocol;
pub mod proxy;
pub mod report;
pub mod rules;
pub mod scrub;
pub mod secret;
pub mod server;
pub mod sites;
pub mod solana;
pub mod store;
pub mod stream;
pub mod totp;
pub mod tron;
pub mod vault;
pub mod wallet;

/// The vault's version, from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The git commit this build came from (set by build.rs; "unknown" outside a checkout).
pub const GIT_COMMIT: &str = env!("VAULT_GIT_COMMIT");

/// The target this build is for, e.g. `x86_64-unknown-linux-musl` (set by build.rs).
pub const TARGET: &str = env!("VAULT_TARGET");

/// What `vault --version` prints after the program's name.
pub const VERSION_LINE: &str =
    concat!(env!("CARGO_PKG_VERSION"), " (commit ", env!("VAULT_GIT_COMMIT"), ", ", env!("VAULT_TARGET"), ")");

/// Now, as RFC 3339 in UTC, to the second.
pub fn now_rfc3339() -> String {
    let now = time::OffsetDateTime::now_utc().replace_nanosecond(0).unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    now.format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| "unknown".into())
}

/// Now, in Unix milliseconds (a Tron transaction's times).
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Now, in Unix seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
