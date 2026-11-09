//! The local socket's protocol: one JSON request per connection, one JSON reply line back.
//!
//! Requests (the only three, safe for any caller on this Mac):
//!   {"op":"list"}
//!   {"op":"totp","name":"github-2fa"}
//!   {"op":"proxy","name":"openai","method":"GET","path":"/v1/models",
//!    "headers":{"accept":"application/json"},"body":"..."}            (or "body_base64")
//!
//! No reply type has a field that could carry a secret value (R4): `SecretValue` doesn't
//! implement `Serialize`, so it can't appear in any of them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::VaultError;
use crate::model::SecretSummary;

pub const MAX_REQUEST_LINE: usize = 2 * 1024 * 1024;

#[derive(Deserialize, Debug)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    List,
    Totp {
        name: String,
    },
    Proxy {
        name: String,
        method: String,
        path: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        #[serde(default)]
        body: Option<String>,
        #[serde(default)]
        body_base64: Option<String>,
    },
}

#[derive(Serialize)]
pub struct ListReply {
    pub ok: bool,
    pub secrets: Vec<SecretSummary>,
}

#[derive(Serialize)]
pub struct TotpReply {
    pub ok: bool,
    pub name: String,
    pub code: String,
    pub seconds_left: u64,
}

#[derive(Serialize)]
pub struct ProxyReplyOut {
    pub ok: bool,
    pub status: u16,
    pub headers: Vec<[String; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
}

#[derive(Serialize)]
pub struct ErrorReply {
    pub ok: bool,
    pub error: &'static str,
    pub message: String,
}

impl ErrorReply {
    pub fn from(error: &VaultError) -> Self {
        ErrorReply { ok: false, error: error.code(), message: error.to_string() }
    }
}
