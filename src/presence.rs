//! The person's own confirmation for their sensitive acts (#7689, R46): Touch ID, or the login
//! password when Touch ID isn't set up or they choose it, through LocalAuthentication
//! (`deviceOwnerAuthentication`), shown by the vault's daemon itself with the reason in words.
//!
//! Only these acts ask, never an agent's path:
//! - showing a saved login's password to the person (`reveal`, R45);
//! - an export of secrets in clear;
//! - using a saved card (#7690);
//! - changing a saved login's site (`update_login`, R47), which moves where its password is filled.
//!
//! `fill` to a matching site, `lease`, `stream`, `proxy`, `totp` and `sign` never ask: agents use
//! them unattended. No process can press Touch ID for the person, so a caller that isn't the
//! person, an agent included, can at most put the request on their screen.
//!
//! One at a time: while a confirmation is on the screen, another is refused (`busy`), so nothing
//! can stack them. A `test-stubs` build never shows one: `VAULT_TEST_PRESENCE=yes` stands in for
//! the person confirming, anything else for declining.

use std::sync::Mutex;

use crate::error::VaultError;
use crate::platform::Peer;

/// How long the person has to answer.
const ANSWER_SECONDS: i32 = 60;

/// The longest reason shown, in characters.
const MAX_REASON_CHARS: usize = 200;

/// One confirmation on the screen at a time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// The reason as the dialog shows it, after "vault is trying to": printable, at most 200
/// characters. LocalAuthentication shows it as given.
pub fn reason_text(reason: &str) -> String {
    reason.chars().filter(|c| !c.is_control()).take(MAX_REASON_CHARS).collect()
}

/// Who asked, for the reason: the caller's program (its file name, a hint as in R23) and pid.
pub fn caller_text(peer: &Peer) -> String {
    let program = peer
        .program
        .as_deref()
        .map(|path| path.rsplit('/').next().unwrap_or(path).to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "an unknown program".into());
    match peer.pid {
        Some(pid) => format!("{program} (pid {pid})"),
        None => program,
    }
}

/// The whole reason: the act, then who asked, so the person sees both (e.g. "show the password
/// of the saved login \"acme-shop\" (acme.com), asked by Volgenic (pid 4242)").
pub fn reason_for(act: &str, peer: &Peer) -> String {
    format!("{act}, asked by {}", caller_text(peer))
}

/// Asks the person at this Mac to confirm `act` (e.g. "show the password of the saved login
/// \"acme-shop\" (acme.com)"), naming the caller `peer` too, and waits for them, at most a
/// minute. `Ok` only when they did.
pub fn confirm(act: &str, peer: &Peer) -> Result<(), VaultError> {
    if act.trim().is_empty() {
        return Err(VaultError::BadRequest("a confirmation needs a reason".into()));
    }
    let reason = reason_text(&reason_for(act, peer));
    if reason.is_empty() {
        return Err(VaultError::BadRequest("a confirmation needs a reason".into()));
    }
    let _guard = ONE_AT_A_TIME.try_lock().map_err(|_| VaultError::Busy)?;
    ask(&reason)
}

#[cfg(all(target_os = "macos", not(feature = "test-stubs")))]
fn ask(reason: &str) -> Result<(), VaultError> {
    unsafe extern "C" {
        fn vault_la_confirm(reason: *const std::ffi::c_char, seconds: i32) -> i32;
    }
    let reason = std::ffi::CString::new(reason).map_err(|_| VaultError::BadRequest("the reason holds a NUL".into()))?;
    match unsafe { vault_la_confirm(reason.as_ptr(), ANSWER_SECONDS) } {
        0 => Ok(()),
        1 => Err(VaultError::NotConfirmed(
            "this Mac can't ask for Touch ID or the login password here (no one is logged in at the screen)".into(),
        )),
        _ => Err(VaultError::NotConfirmed(format!("declined, cancelled or no answer in {ANSWER_SECONDS} s"))),
    }
}

#[cfg(feature = "test-stubs")]
fn ask(_reason: &str) -> Result<(), VaultError> {
    let _ = ANSWER_SECONDS;
    match std::env::var("VAULT_TEST_PRESENCE").as_deref() {
        Ok("yes") => Ok(()),
        _ => Err(VaultError::NotConfirmed("declined (the stand-in, VAULT_TEST_PRESENCE)".into())),
    }
}

/// Linux: no screen to ask on, so no sensitive act that needs the person is offered there.
#[cfg(all(not(target_os = "macos"), not(feature = "test-stubs")))]
fn ask(_reason: &str) -> Result<(), VaultError> {
    let _ = ANSWER_SECONDS;
    Err(VaultError::UnsupportedPlatform("confirming with Touch ID or the login password".into()))
}
