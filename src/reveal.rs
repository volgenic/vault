//! `reveal` (#7666): gives a stored login's password or an API key's value back to whoever asks,
//! with a reason, audited before the value leaves.
//!
//! This is the owner's deliberate exception to "values never leave the vault" (R4), made on
//! 2026-11-17 so that he and his agents can read a password instead of resetting it. Everything
//! else stays: only a `login` or an `api-key` is revealed (a 2FA seed, a plan token, a Codex or
//! Grok login, personal details, an app secret and a wallet key never are); every reveal needs a
//! reason; its audit line, with the reason and the caller, is on disk before the value is sent,
//! and when it can't be written nothing is sent (`audit_unavailable`, R28). The value is in the
//! reply line only: never in the audit log, an error or the daemon's log, and nothing caches it.

use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::model::{Kind, Record, SecretRef, VaultDoc};
use crate::secret::SecretValue;

/// The longest reason the audit log keeps, in characters.
pub const MAX_REASON: usize = 500;
/// The longest caller hint, in characters.
pub const MAX_CALLER: usize = 128;

/// Whether `reveal` gives this kind's value back: a login's password and an API key's value only.
pub fn may_reveal(kind: Kind) -> bool {
    matches!(kind, Kind::Login | Kind::ApiKey)
}

/// Checks a reveal's reason and caller hint and returns them trimmed: a reason is required, 1 to
/// `MAX_REASON` characters with no control character; a caller, if given, 1 to `MAX_CALLER`.
pub fn check_request(reason: Option<&str>, caller: Option<&str>) -> Result<(String, Option<String>), VaultError> {
    let reason = reason.map(str::trim).unwrap_or("");
    if reason.is_empty() {
        return Err(VaultError::BadRequest("reveal needs a reason: say why you need the value".into()));
    }
    if reason.chars().count() > MAX_REASON || reason.chars().any(char::is_control) {
        return Err(VaultError::BadRequest(format!(
            "the reason must be at most {MAX_REASON} characters, on one line"
        )));
    }
    let caller = match caller.map(str::trim) {
        None | Some("") => None,
        Some(caller) if caller.chars().count() > MAX_CALLER || caller.chars().any(char::is_control) => {
            return Err(VaultError::BadRequest(format!("the caller must be at most {MAX_CALLER} characters, on one line")));
        }
        Some(caller) => Some(caller.to_string()),
    };
    Ok((reason.to_string(), caller))
}

/// The record a reveal names, if its kind may be revealed (`wrong_kind` otherwise).
pub(crate) fn find<'a>(doc: &'a VaultDoc, secret: &SecretRef) -> Result<&'a Record, VaultError> {
    let record = doc.find_ref(secret).ok_or_else(|| secret.not_found())?;
    if !may_reveal(record.kind) {
        return Err(VaultError::WrongKind);
    }
    Ok(record)
}

/// `reveal`'s answer. The value is borrowed from the record and written straight into the reply
/// line (`server::reply_secret`), which is wiped after sending: no copy of it is kept. This and
/// `crate::client::Revealed` are the reveal call sites of `expose` in R1.
#[derive(Serialize)]
pub struct RevealReply<'a> {
    pub ok: bool,
    pub id: &'a str,
    pub name: &'a str,
    pub kind: Kind,
    pub site: &'a str,
    pub version: u64,
    /// A login's username; null for an API key.
    pub username: Option<&'a str>,
    /// The password or key, when it is text (every value typed or sealed is).
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "text_ref")]
    pub value: Option<&'a SecretValue>,
    /// The value as base64, only when it isn't UTF-8 text; then `value` is left out.
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "base64_text")]
    pub value_base64: Option<Zeroizing<String>>,
}

impl<'a> RevealReply<'a> {
    pub(crate) fn of(record: &'a Record) -> Self {
        let text = std::str::from_utf8(record.value.expose()).is_ok();
        RevealReply {
            ok: true,
            id: &record.id,
            name: &record.name,
            kind: record.kind,
            site: &record.site,
            version: record.version,
            username: if record.kind == Kind::Login { record.username.as_deref() } else { None },
            value: text.then_some(&record.value),
            value_base64: (!text).then(|| {
                use base64::Engine;
                Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(record.value.expose()))
            }),
        }
    }
}

fn text_ref<S: serde::Serializer>(value: &Option<&SecretValue>, serializer: S) -> Result<S::Ok, S::Error> {
    match value.map(|value| std::str::from_utf8(value.expose())) {
        Some(Ok(text)) => serializer.serialize_str(text),
        _ => serializer.serialize_none(),
    }
}

fn base64_text<S: serde::Serializer>(value: &Option<Zeroizing<String>>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(text) => serializer.serialize_str(text),
        None => serializer.serialize_none(),
    }
}
