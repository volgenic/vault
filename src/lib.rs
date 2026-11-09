//! The vault's platform-neutral library: decisions over plain values. Keychain and Secure Enclave
//! code stays behind one small key-protection module, never spread through this crate.

/// The vault's version, from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
