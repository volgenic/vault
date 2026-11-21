//! Filling a saved login into the in-app browser (#7663): the one way a login's password leaves
//! the vault. The decisions are pure functions here; the daemon (`server`) reads the request,
//! writes the audit line and answers.
//!
//! The browser engine that types (Volgenic for Mac's WebKit engine, or the host daemon's Chrome
//! engine) asks the vault itself, naming the login and the origin of the frame that holds the
//! fields, as the browser reports it where the page can't change it:
//!
//! ```json
//! {"protocol":2,"op":"fill","name":"acme-shop","origin":"https://accounts.acme.com",
//!  "fields":["username","password"],"engine":"app","tab":"w3","on_behalf_of":"agent @x"}
//! ```
//!
//! The vault answers the values only when the name is a login and the origin is `https:` on the
//! login's registrable domain (`sites`), and only after the `fill` line is on disk (R28):
//!
//! ```json
//! {"ok":true,"name":"acme-shop","id":"...","site":"acme.com","site_matched":"acme.com",
//!  "values":{"username":"sales@example.com","password":"..."},"protocol":2}
//! ```
//!
//! That reply is written by hand into a wiped buffer, never through a formatter (R1), and is the
//! one reply that carries a value in clear (R4). The engine types the values into the page and
//! nowhere else; the daemon, the hub and the agent get only what was filled.

use crate::error::VaultError;
use crate::model::{Kind, Record};
use crate::protocol::{Envelope, PROTOCOL_VERSION};
use crate::secret::WipingBuf;

/// The longest `engine`, `tab` or `on_behalf_of`, which go to the audit line only.
pub const MAX_NOTE_CHARS: usize = 128;

/// A field a fill may ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Username,
    Password,
}

impl Field {
    pub fn label(self) -> &'static str {
        match self {
            Field::Username => "username",
            Field::Password => "password",
        }
    }
}

/// The fields a request names: `username` and/or `password`, each once, at least one. A
/// two-step sign-in asks for the username alone, then the password alone.
pub fn parse_fields(names: &[String]) -> Result<Vec<Field>, VaultError> {
    let mut fields = Vec::new();
    for name in names {
        let field = match name.as_str() {
            "username" => Field::Username,
            "password" => Field::Password,
            _ => return Err(VaultError::BadRequest("fields are \"username\" and/or \"password\"".into())),
        };
        if fields.contains(&field) {
            return Err(VaultError::BadRequest("fields names a field more than once".into()));
        }
        fields.push(field);
    }
    if fields.is_empty() {
        return Err(VaultError::BadRequest("fields names at least one of \"username\" and \"password\"".into()));
    }
    // Always in the same order, username first, whatever order they came in.
    fields.sort_by_key(|field| *field == Field::Password);
    Ok(fields)
}

/// Whether a fill must come from Volgenic for Mac's signed app (#7689): one that says it is the
/// app (`engine:"app"`) is checked to be it (`platform::peer_is_volgenic_app`). The host daemon's
/// Chrome engine keeps the owner's-user-ID check alone (R22).
pub fn needs_signed_app(engine: Option<&str>) -> bool {
    engine == Some("app")
}

/// A note for the audit line (`engine`, `tab`, `on_behalf_of`): printable, at most 128 characters.
pub fn note(text: Option<String>) -> Option<String> {
    text.map(|text| text.chars().filter(|c| !c.is_control()).take(MAX_NOTE_CHARS).collect::<String>())
        .filter(|text| !text.is_empty())
}

/// What a fill was checked against: the login's registrable domain and the frame's host.
pub struct Matched {
    pub domain: String,
    pub host: String,
}

/// Checks a fill before anything leaves the vault: the record is a login (`no_such_login`), and
/// the frame's origin is `https:` on the login's registrable domain (`site_mismatch`).
pub(crate) fn check(record: Option<&Record>, label: &str, origin: &str) -> Result<Matched, VaultError> {
    let record = record
        .filter(|record| record.kind == Kind::Login)
        .ok_or_else(|| VaultError::NoSuchLogin(label.to_string()))?;
    let domain = crate::sites::login_domain(&record.site)?;
    let host = crate::sites::check_origin(origin, &domain)?;
    Ok(Matched { domain, host })
}

/// How the audit line describes a fill: never a value.
pub fn describe(fields: &[Field], matched: &Matched, engine: Option<&str>, tab: Option<&str>, on_behalf_of: Option<&str>) -> String {
    let fields: Vec<&str> = fields.iter().map(|field| field.label()).collect();
    let mut text = format!("{} into https://{} (site {})", fields.join(" and "), matched.host, matched.domain);
    if let Some(engine) = engine {
        text.push_str(&format!(", engine {engine}"));
    }
    if let Some(tab) = tab {
        text.push_str(&format!(", tab {tab}"));
    }
    if let Some(on_behalf_of) = on_behalf_of {
        text.push_str(&format!(", on behalf of {on_behalf_of}"));
    }
    text
}

/// The reply line, written straight into a wiped buffer (R1): the login's name, id and site, the
/// matched domain, the values asked for, the protocol and the request id, then a line break.
/// A password that isn't UTF-8 text can't go into JSON, so it is refused (`invalid_secret`).
pub(crate) fn reply_line(record: &Record, fields: &[Field], matched: &Matched, envelope: &Envelope) -> Result<WipingBuf, VaultError> {
    let text = |value: &str| serde_json::to_vec(value).unwrap_or_else(|_| b"\"\"".to_vec());
    let username = record.username.as_deref().unwrap_or("");
    let password = record.value.expose();
    if fields.contains(&Field::Password) && std::str::from_utf8(password).is_err() {
        return Err(VaultError::InvalidSecret("the login's password isn't text, so it can't be filled".into()));
    }
    let mut out = WipingBuf::with_capacity(password.len() * 6 + username.len() * 6 + 512);
    out.extend_from_slice(b"{\"ok\":true,\"name\":");
    out.extend_from_slice(&text(&record.name));
    out.extend_from_slice(b",\"id\":");
    out.extend_from_slice(&text(&record.id));
    out.extend_from_slice(b",\"site\":");
    out.extend_from_slice(&text(&record.site));
    out.extend_from_slice(b",\"site_matched\":");
    out.extend_from_slice(&text(&matched.domain));
    out.extend_from_slice(b",\"values\":{");
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        let value = match field {
            Field::Username => username.as_bytes(),
            Field::Password => password,
        };
        crate::details::write_field(&mut out, field.label(), value);
    }
    out.extend_from_slice(format!("}},\"protocol\":{PROTOCOL_VERSION}").as_bytes());
    if let Some(request_id) = &envelope.request_id {
        out.extend_from_slice(b",\"request_id\":");
        out.extend_from_slice(&serde_json::to_vec(request_id).unwrap_or_else(|_| b"null".to_vec()));
    }
    out.extend_from_slice(b"}\n");
    Ok(out)
}
