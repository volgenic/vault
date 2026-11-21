//! The local socket's protocol: one JSON request per connection, one JSON reply line back.
//!
//! The daemon accepts connections only from the owner's own user ID, not root (R22). Every
//! agent on the machine runs as the owner, so every request here is open to every agent.
//!
//! **Versions and request ids (protocol 2).** A request may carry `"protocol": 2` and a
//! `"request_id"` (a string of at most 128 printable ASCII characters, or a whole number). Every
//! reply, errors included, carries `"protocol"` (the daemon's version, `PROTOCOL_VERSION`) and
//! echoes the `request_id` exactly as sent. A request with no `protocol` is protocol 1 and is
//! served the same way: everything protocol 2 added is optional on the way in and extra fields
//! on the way out. A request for a newer protocol than the daemon's is refused with
//! `unsupported_protocol`.
//!
//! **Naming a secret.** `totp`, `proxy`, `delete` and `rename` take `"name"` or `"id"` (the
//! secret's stable id from `list`), exactly one of them; `update_login` takes `"id"` only.
//!
//! For agents:
//!   {"op":"list"}
//!   {"op":"totp","name":"github-2fa"}                  (or "id":"<32 hex digits>")
//!   {"op":"proxy","name":"openai","method":"GET","path":"/v1/models",
//!    "headers":{"accept":"application/json"},"body":"..."}            (or "body_base64")
//!   {"op":"proxy","name":"openai","host":"api.openai.com","port":443,"method":"GET",
//!    "path":"/v1/models"}                       (host and port optional; see below)
//!   {"op":"stream","name":"main","method":"POST","path":"/v1/messages?beta=true",
//!    "headers":[["anthropic-version","2023-06-01"]],"body_len":1234}  then 1234 body bytes
//!   {"op":"health"}
//!
//! **`proxy`'s destination.** The key's rule alone decides where a `proxy` call goes. A caller
//! may name the destination it meant, `host` (compared case-insensitively) and `port` (a number
//! or its decimal text; 443 when only `host` is given): when that isn't the rule's, the call is
//! refused `rule_mismatch` before anything is sent, and the refusal is audited with the host
//! asked for, as `stream` refuses one. Without either, the call goes to the rule's host as before.
//!
//! For the host daemon and Volgenic's app (R40, R41):
//!   {"op":"add_sealed","name":"main","kind":"claude_plan","sealed_base64":"...","replace":true}
//!   {"op":"import_plan","plans":[{"name":"main","value":"sk-ant-oat01-..."}]}
//!   {"op":"import_login","logins":[{"name":"codex","kind":"codex_login","auth_json":"{...}"}]}
//!   {"op":"claim_refresh","name":"codex","version":1}                (or "id")
//!   {"op":"lease","job":"build:4812","recipient":"age1...","names":["NPM_TOKEN"],"ttl_seconds":3600}
//!                                                                      (and/or "ids")
//!
//! **`lease`** (#7446) seals each named app secret's value to the job's own age key, with the job
//! and an expiry inside (`lease`), and answers only ciphertext:
//! `{"ok":true,"sealed":[{"name","id","sealed_base64"}],"missing":[...],"expires_at","job"}`. A
//! secret it holds that may not be leased refuses the whole request:
//! `{"ok":false,"error":"not_leasable","message","names":[...]}`.
//!
//! For the browser engines that type a saved login into a page, Volgenic for Mac's and the host
//! daemon's Chrome (#7663, R37, R38):
//!   {"op":"fill","name":"acme-shop","origin":"https://accounts.acme.com","fields":["username","password"],
//!    "engine":"app","tab":"w3","on_behalf_of":"agent @x"}         (or "id"; the last three optional)
//!   {"op":"generate_login","name":"acme-shop","site":"acme.com","username":"sales@example.com","length":20}
//!
//! **`fill`** answers the login's values, in clear, only when `origin` (the frame holding the
//! fields, as the browser reports it) is `https:` on the login's registrable domain, and only
//! after its audit line is on disk: `{"ok":true,"name","id","site","site_matched","values":
//! {"username"?,"password"?}}` (`fill`). **`generate_login`** stores a login with a password the
//! vault makes, and answers `{"ok":true,"secret":{...},"backup":{...}}`, never the password.
//!
//! For Volgenic for Mac's Passwords screen (#7696, R47):
//!   {"op":"update_login","id":"<id>","username":"new@example.com","site":"acme.com"}
//!                                       (username, site or both; the id only, never the name)
//!
//! **`update_login`** changes a login's username or site, never its password; a site change only
//! after the person confirms it with Touch ID or their login password (R46, `not_confirmed` when
//! they don't). It keeps the id and value, raises the version, and answers `{"ok":true,"secret":{...},"changed":["username","site"],
//! "backup":{...}}`. A request that changes nothing answers `"changed":[]` with no `backup` and
//! writes nothing. It has no sealed form: `add_sealed` can't replace a stored login (R40).
//!
//! For the host daemon's payment relay (#7440, #7490), and the command line for the two that need
//! the recovery key:
//!   {"op":"sign","name":"main-wallet","chain":"ethereum","token":"USDC",
//!    "to":"0x...","amount":"12.50","nonce":7,"gas_limit":78000,
//!    "max_fee_per_gas":30000000000,"max_priority_fee_per_gas":1500000000,
//!    "ladder":4,"ladder_max_fee_per_gas":45000000000,"on_behalf_of":"agent @x, item #123"}
//!                                       (or "id"; ladder, its ceiling and on_behalf_of optional)
//!   {"op":"sign","name":"sol-wallet","chain":"solana","token":"USDC","to":"<base58 wallet>",
//!    "amount":"12.50","recent_blockhash":"<base58>","compute_unit_limit":60000,
//!    "compute_unit_price":50000,"create_recipient_account":true}   (price and create optional)
//!   {"op":"sign","name":"tron-wallet","chain":"tron","token":"USDT","to":"T...","amount":"12.50",
//!    "ref_block_num":87350971,"ref_block_id":"<64 hex>","timestamp":<ms>,"expiration":<ms>,
//!    "fee_limit":20000000}
//!   {"op":"wallet_create","name":"main-wallet","chain":"ethereum","caps":{...},"recovery_key":"AGE-SECRET-KEY-1..."}
//!   {"op":"wallet_caps","name":"main-wallet","caps":{...},"recovery_key":"AGE-SECRET-KEY-1..."}
//!
//! **`sign`** (`wallet`) signs one token transfer the vault builds itself from those fields,
//! within the wallet's caps, and answers the signed transaction and, on Ethereum, its ladder (the
//! same transfer at rising fees, for the relay to send if the first stalls):
//! `{"ok":true,"signed":{"raw","hash",...},"ladder":[...],...}`. A field of another chain than the
//! wallet's is `bad_request`. Over a cap it answers `over_cap` and signs nothing.
//!
//! **A cancel** (#7491), Ethereum only, is `sign` with `"cancel":true`, `chain`, `nonce` and fees
//! (and the same optional `ladder`, its ceiling and `on_behalf_of`), and no `to`, `token`,
//! `amount` or Solana or Tron field:
//!   {"op":"sign","name":"main-wallet","cancel":true,"chain":"ethereum","nonce":7,
//!    "max_fee_per_gas":40000000000,"max_priority_fee_per_gas":2500000000,"ladder":2}
//! The vault signs a 0-ETH transfer from the wallet to itself, 21,000 gas and no data, only at a
//! nonce it signed a payment for in the last day, and answers
//! `{"ok":true,"cancel":true,"signed":{...},"ladder":[...],"cancels":[...],...}`.
//!
//! `caps` is `{"per_payment_micros","daily_micros"}` plus the wallet's chain's fee caps:
//! `"max_fee_per_gas","daily_fees_wei"` (Ethereum), `"max_compute_unit_price","daily_fees_lamports"`
//! (Solana), `"max_fee_limit_sun","daily_fees_sun"` (Tron). Dollars are in millionths, fees in the
//! chain's smallest unit, JSON numbers up to 2^64.
//!
//! **`stream`** (R39) sends one request with a credential whose kind (`kinds`) or rule (an API key)
//! decides the host, the methods, the paths and the headers the vault sets, and streams the reply
//! back as it arrives. Its body follows the request line as raw bytes, exactly `body_len` of them
//! (at most `stream::MAX_BODY`). The reply is a head line, the body in chunks, and a trailer line:
//!
//! ```text
//! {"ok":true,"status":200,"headers":[["content-type","text/event-stream"],...],"protocol":2,...}
//! <length in decimal>\n<that many bytes>          (repeated, as the upstream sends them)
//! 0\n
//! {"ok":true,"end":"complete","bytes":123456,"protocol":2,...}
//! ```
//!
//! A refusal before anything is sent upstream, or an upstream failure before its reply's head,
//! is one error line, as for every op. A trailer with `"ok":false` ends a reply that was cut short:
//! `end` is `idle_timeout`, `upstream_failed` or `echo_blocked`. A caller that hangs up cancels the
//! call; the vault closes the upstream connection.
//!
//! For the command-line tool (R13: only the daemon changes the vault; R26):
//!   status, audit, add, delete, rename, confirm-kit, reset, restore,
//!   backup         write this generation's backup if it isn't written yet, and verify it
//!   verify-backup  decrypt the newest backup with the check key and compare it
//!   read-backup    the newest backup's encrypted bytes, for checks with the recovery key
//!                  that the command-line tool makes itself
//!
//! For the owner's mirror agent (R32): mirror-plan, mirror-report.
//!
//! `restore` with a file sends the file's bytes right after its request line, as they are.
//!
//! `add`, `confirm-kit`, `reset` and `restore` carry a typed value or the recovery key. The
//! command-line tool sends them only after checking that the socket and the process behind it
//! are its own user's (R22, R27).
//!
//! No reply type has a field that could carry a secret value (R4): `SecretValue` doesn't
//! implement `Serialize`, so it can't appear in any of them. Two exceptions are written by hand,
//! never through a reply type: `lease` answers app secrets sealed to the job's own key
//! (`lease::seal`), which only that key opens, and `fill` answers a login's values to the browser
//! engine that types them, once the page's site matches (`fill::reply_line`). A wallet's key is
//! in no reply at all, sealed or not; `sign` answers signatures.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::audit::AuditLine;
use crate::error::VaultError;
use crate::kinds::HealthState;
use crate::model::{self, BackupStatus, Kind, MirrorState, SecretRef, SecretSummary, secret_bytes};
use crate::secret::SecretValue;

pub const MAX_REQUEST_LINE: usize = 2 * 1024 * 1024;

/// The protocol this build speaks. 1 is the protocol of pull requests #2 to #4 (no version, no
/// request id, secrets by name only); 2 adds the version, request ids, secret ids and `rename`.
pub const PROTOCOL_VERSION: u32 = 2;

/// What every request carries besides its operation: its protocol version and request id.
#[derive(Clone, Debug)]
pub struct Envelope {
    /// 1 when the request didn't say.
    pub protocol: u32,
    /// Exactly as the caller sent it, to echo back.
    pub request_id: Option<serde_json::Value>,
}

impl Default for Envelope {
    fn default() -> Self {
        Envelope { protocol: 1, request_id: None }
    }
}

impl Envelope {
    /// The request id as the audit log records it.
    pub fn request_id_text(&self) -> Option<String> {
        match &self.request_id {
            Some(serde_json::Value::String(text)) => Some(text.clone()),
            Some(other) => Some(other.to_string()),
            None => None,
        }
    }
}

/// Reads the envelope alone; every other field is skipped without being kept (R1). Returns the
/// envelope even when it is unacceptable, so the refusal can still echo an acceptable request id.
pub fn parse_envelope(line: &[u8]) -> (Envelope, Result<(), VaultError>) {
    #[derive(Deserialize)]
    struct Wire {
        #[serde(default)]
        protocol: Option<serde_json::Value>,
        #[serde(default)]
        request_id: Option<serde_json::Value>,
    }
    let Ok(wire) = serde_json::from_slice::<Wire>(line) else {
        return (Envelope::default(), Err(VaultError::BadRequest("not a JSON object".into())));
    };
    let request_id = wire.request_id.filter(|value| !value.is_null());
    let id_ok = match &request_id {
        None => true,
        Some(serde_json::Value::String(text)) => {
            !text.is_empty() && text.len() <= 128 && text.bytes().all(|b| (0x20..0x7f).contains(&b))
        }
        Some(serde_json::Value::Number(number)) => number.is_u64(),
        Some(_) => false,
    };
    // No `protocol` is protocol 1; anything but a whole number from 1 is malformed (`None`).
    let protocol = match &wire.protocol {
        None => Some(1),
        Some(value) => value.as_u64().and_then(|v| u32::try_from(v).ok()).filter(|v| *v >= 1),
    };
    let envelope = Envelope { protocol: protocol.unwrap_or(1), request_id: request_id.filter(|_| id_ok) };
    let result = match protocol {
        _ if !id_ok => Err(VaultError::BadRequest(
            "request_id is a string of 1 to 128 printable ASCII characters, or a whole number".into(),
        )),
        None => Err(VaultError::BadRequest("protocol is a whole number from 1".into())),
        Some(version) if version > PROTOCOL_VERSION => Err(VaultError::UnsupportedProtocol(version)),
        Some(_) => Ok(()),
    };
    (envelope, result)
}

/// A reply as it goes on the wire: the reply's own fields, plus the protocol version and the
/// request's id.
#[derive(Serialize)]
pub struct Framed<'a, T: Serialize> {
    #[serde(flatten)]
    pub body: &'a T,
    pub protocol: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<&'a serde_json::Value>,
}

/// What the command-line tool reads of every reply before the reply itself.
#[derive(Deserialize)]
pub struct ReplyFrame {
    #[serde(default)]
    pub protocol: Option<u32>,
    #[serde(default)]
    pub request_id: Option<serde_json::Value>,
}

/// An API key's rule as the person typed it. The daemon parses and checks it (R7); it never
/// takes a ready-made rule from a caller.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RuleInput {
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub methods: Vec<String>,
    pub path: String,
    pub header: String,
}

/// A request, as `parse_request` reads it.
#[derive(Debug)]
pub enum Request {
    List,
    Totp {
        secret: SecretRef,
    },
    Proxy {
        secret: SecretRef,
        /// The destination the caller meant, if it names one: refused unless it's the key's
        /// rule's (`rules::check_destination`). Left out, the rule's host and port.
        host: Option<String>,
        port: Option<u16>,
        method: String,
        path: String,
        headers: BTreeMap<String, String>,
        body: Option<String>,
        body_base64: Option<String>,
    },
    Stream {
        secret: SecretRef,
        /// One of the kind's hosts; the first when not given. An API key's is its rule's.
        host: Option<String>,
        method: String,
        path: String,
        /// In the caller's order; a name may repeat.
        headers: Vec<(String, String)>,
        /// How many raw body bytes follow the request line.
        body_len: usize,
        idle_timeout_secs: Option<u64>,
    },
    Health,
    AddSealed {
        name: String,
        kind: Kind,
        sealed_base64: String,
        replace: bool,
    },
    ImportPlan {
        plans: Vec<(String, SecretValue)>,
    },
    /// The host's Codex and Grok `auth.json` files, whole: name, kind, contents.
    ImportLogin {
        logins: Vec<(String, Kind, SecretValue)>,
    },
    ClaimRefresh {
        secret: SecretRef,
        /// The version `import_login` gave the login.
        version: u64,
    },
    Lease {
        job: String,
        recipient: String,
        /// The names, then the ids, as given.
        secrets: Vec<SecretRef>,
        ttl_seconds: u64,
    },
    Sign {
        secret: SecretRef,
        fields: SignFields,
    },
    /// `sign` with `"cancel":true` (#7491).
    SignCancel {
        secret: SecretRef,
        chain: String,
        /// The payment fields the caller sent, which a cancel refuses: `to`, `token`, `amount`.
        extra: Vec<&'static str>,
        gas_limit: Option<u64>,
        nonce: u64,
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
        ladder: usize,
        ladder_max_fee_per_gas: Option<u64>,
        on_behalf_of: Option<String>,
    },
    /// A browser engine asks for a login's values to type (#7663).
    Fill {
        secret: SecretRef,
        /// The origin of the frame that holds the fields, as the browser reports it.
        origin: String,
        fields: Vec<String>,
        /// For the audit line only: which engine, which tab, for whom.
        engine: Option<String>,
        tab: Option<String>,
        on_behalf_of: Option<String>,
    },
    /// A login's new username or site, never its password (#7696).
    UpdateLogin {
        secret: SecretRef,
        username: Option<String>,
        site: Option<String>,
    },
    /// A new login with a password the vault makes (#7663).
    GenerateLogin {
        name: String,
        site: String,
        username: String,
        length: Option<usize>,
    },
    WalletCreate {
        name: String,
        chain: String,
        caps: crate::wallet::Caps,
        recovery_key: SecretValue,
    },
    WalletCaps {
        secret: SecretRef,
        caps: crate::wallet::Caps,
        recovery_key: SecretValue,
    },
    Status,
    Audit {
        all: bool,
    },
    Add {
        name: String,
        kind: Kind,
        site: String,
        rule: Option<RuleInput>,
        username: Option<String>,
        app: Option<String>,
        leasable: bool,
        value: SecretValue,
    },
    Delete {
        secret: SecretRef,
    },
    Rename {
        secret: SecretRef,
        new_name: String,
    },
    ConfirmKit {
        recovery_key: SecretValue,
    },
    Reset {
        recovery_key: Option<SecretValue>,
    },
    Restore {
        recovery_key: SecretValue,
        /// The size of a backup file the person named (`vault restore FILE`). Its bytes follow
        /// the request line as they are, up to `backup::MAX_BACKUP_BYTES`. Without it, the
        /// restore point `vault reset` kept.
        backup_len: Option<usize>,
        source: Option<String>,
    },
    Backup,
    VerifyBackup,
    ReadBackup,
    MirrorPlan,
    MirrorReport {
        ok: bool,
        newest_file: Option<String>,
        newest_generation: Option<u64>,
        copied: usize,
        already_there: usize,
        detail: String,
    },
}

/// Parses one request line (R1). Serde's `#[serde(tag = "op")]` enums first copy every field
/// into an intermediate buffer of their own, which nothing wipes, so a typed value or recovery
/// key would be left behind in freed memory. Instead this reads `op` alone (skipping the other
/// fields without keeping them), then deserializes the line again straight into that
/// operation's own struct, whose secret fields go directly into wiping buffers.
pub fn parse_request(line: &[u8]) -> Result<Request, serde_json::Error> {
    use serde::de::Error;

    #[derive(Deserialize)]
    struct Op {
        op: String,
    }

    #[derive(Deserialize)]
    struct Named {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        id: Option<String>,
    }

    #[derive(Deserialize)]
    struct RenameWire {
        new_name: String,
    }

    #[derive(Deserialize)]
    struct ProxyWire {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        host: Option<String>,
        #[serde(default)]
        port: Option<PortWire>,
        method: String,
        path: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        #[serde(default)]
        body: Option<String>,
        #[serde(default)]
        body_base64: Option<String>,
    }

    /// A port as a number or as its decimal text (a URL's port is often kept as text).
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PortWire {
        Number(u16),
        Text(String),
    }

    impl PortWire {
        fn port(self) -> Result<u16, serde_json::Error> {
            match self {
                PortWire::Number(port) => Ok(port),
                PortWire::Text(text) => text.parse().map_err(|_| serde_json::Error::custom("port isn't a port number")),
            }
        }
    }

    /// Headers as `[[name, value], ...]` (order kept, names may repeat) or as an object.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum HeadersWire {
        List(Vec<(String, String)>),
        Map(BTreeMap<String, String>),
    }

    #[derive(Deserialize)]
    struct StreamWire {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        host: Option<String>,
        method: String,
        path: String,
        #[serde(default)]
        headers: Option<HeadersWire>,
        #[serde(default)]
        body_len: usize,
        #[serde(default)]
        idle_timeout_secs: Option<u64>,
    }

    #[derive(Deserialize)]
    struct AddSealedWire {
        name: String,
        kind: Kind,
        sealed_base64: String,
        #[serde(default)]
        replace: bool,
    }

    #[derive(Deserialize)]
    struct PlanWire {
        name: String,
        /// A JSON string or an array of bytes, read straight into a wiping buffer (R1).
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        value: SecretValue,
    }

    #[derive(Deserialize)]
    struct ImportWire {
        plans: Vec<PlanWire>,
    }

    #[derive(Deserialize)]
    struct LoginWire {
        name: String,
        kind: Kind,
        /// The auth.json's text as a JSON string (or an array of its bytes), read straight into a
        /// wiping buffer (R1).
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        auth_json: SecretValue,
    }

    #[derive(Deserialize)]
    struct ImportLoginWire {
        logins: Vec<LoginWire>,
    }

    #[derive(Deserialize)]
    struct LeaseWire {
        job: String,
        recipient: String,
        #[serde(default)]
        names: Vec<String>,
        #[serde(default)]
        ids: Vec<String>,
        ttl_seconds: u64,
    }

    #[derive(Deserialize)]
    struct FillWire {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        id: Option<String>,
        origin: String,
        fields: Vec<String>,
        #[serde(default)]
        engine: Option<String>,
        #[serde(default)]
        tab: Option<String>,
        #[serde(default)]
        on_behalf_of: Option<String>,
    }

    #[derive(Deserialize)]
    struct UpdateLoginWire {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        site: Option<String>,
    }

    #[derive(Deserialize)]
    struct GenerateLoginWire {
        name: String,
        site: String,
        username: String,
        #[serde(default)]
        length: Option<usize>,
    }

    #[derive(Deserialize)]
    struct WalletCreateWire {
        name: String,
        chain: String,
        caps: crate::wallet::Caps,
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        recovery_key: SecretValue,
    }

    #[derive(Deserialize)]
    struct WalletCapsWire {
        caps: crate::wallet::Caps,
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        recovery_key: SecretValue,
    }

    #[derive(Deserialize)]
    struct ClaimWire {
        version: u64,
    }

    #[derive(Deserialize)]
    struct AuditWire {
        #[serde(default)]
        all: bool,
    }

    #[derive(Deserialize)]
    struct AddWire {
        name: String,
        kind: Kind,
        site: String,
        #[serde(default)]
        rule: Option<RuleInput>,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        app: Option<String>,
        #[serde(default)]
        leasable: bool,
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        value: SecretValue,
    }

    #[derive(Deserialize)]
    struct ConfirmKitWire {
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        recovery_key: SecretValue,
    }

    #[derive(Deserialize)]
    struct ResetWire {
        #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
        recovery_key: Option<SecretValue>,
    }

    #[derive(Deserialize)]
    struct RestoreWire {
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        recovery_key: SecretValue,
        #[serde(default)]
        backup_len: Option<usize>,
        #[serde(default)]
        source: Option<String>,
    }

    #[derive(Deserialize)]
    struct MirrorReportWire {
        ok: bool,
        #[serde(default)]
        newest_file: Option<String>,
        #[serde(default)]
        newest_generation: Option<u64>,
        #[serde(default)]
        copied: usize,
        #[serde(default)]
        already_there: usize,
        #[serde(default)]
        detail: String,
    }

    /// Exactly one of `name` and `id`.
    fn secret_ref(name: Option<String>, id: Option<String>) -> Result<SecretRef, serde_json::Error> {
        match (name, id) {
            (Some(name), None) => Ok(SecretRef::Name(name)),
            (None, Some(id)) => {
                model::validate_id(&id).map_err(|_| serde_json::Error::custom("an id is 32 lower-case hex digits"))?;
                Ok(SecretRef::Id(id))
            }
            _ => Err(serde_json::Error::custom("give name or id, exactly one")),
        }
    }
    let named = |line: &[u8]| -> Result<SecretRef, serde_json::Error> {
        let w: Named = serde_json::from_slice(line)?;
        secret_ref(w.name, w.id)
    };

    let op = serde_json::from_slice::<Op>(line)?.op;
    Ok(match op.as_str() {
        "list" => Request::List,
        "status" => Request::Status,
        "backup" => Request::Backup,
        "verify-backup" => Request::VerifyBackup,
        "read-backup" => Request::ReadBackup,
        "mirror-plan" => Request::MirrorPlan,
        "totp" => Request::Totp { secret: named(line)? },
        "delete" => Request::Delete { secret: named(line)? },
        "rename" => Request::Rename {
            secret: named(line)?,
            new_name: serde_json::from_slice::<RenameWire>(line)?.new_name,
        },
        "proxy" => {
            let w: ProxyWire = serde_json::from_slice(line)?;
            Request::Proxy {
                secret: secret_ref(w.name, w.id)?,
                host: w.host,
                port: w.port.map(PortWire::port).transpose()?,
                method: w.method,
                path: w.path,
                headers: w.headers,
                body: w.body,
                body_base64: w.body_base64,
            }
        }
        "stream" => {
            let w: StreamWire = serde_json::from_slice(line)?;
            let headers = match w.headers {
                None => Vec::new(),
                Some(HeadersWire::List(list)) => list,
                Some(HeadersWire::Map(map)) => map.into_iter().collect(),
            };
            Request::Stream {
                secret: secret_ref(w.name, w.id)?,
                host: w.host,
                method: w.method,
                path: w.path,
                headers,
                body_len: w.body_len,
                idle_timeout_secs: w.idle_timeout_secs,
            }
        }
        "health" => Request::Health,
        "add_sealed" => {
            let w: AddSealedWire = serde_json::from_slice(line)?;
            Request::AddSealed { name: w.name, kind: w.kind, sealed_base64: w.sealed_base64, replace: w.replace }
        }
        "import_plan" => {
            let w: ImportWire = serde_json::from_slice(line)?;
            Request::ImportPlan { plans: w.plans.into_iter().map(|plan| (plan.name, plan.value)).collect() }
        }
        "import_login" => {
            let w: ImportLoginWire = serde_json::from_slice(line)?;
            Request::ImportLogin { logins: w.logins.into_iter().map(|login| (login.name, login.kind, login.auth_json)).collect() }
        }
        "claim_refresh" => Request::ClaimRefresh {
            secret: named(line)?,
            version: serde_json::from_slice::<ClaimWire>(line)?.version,
        },
        "lease" => {
            let w: LeaseWire = serde_json::from_slice(line)?;
            let secrets = w.names.into_iter().map(SecretRef::Name).chain(w.ids.into_iter().map(SecretRef::Id)).collect();
            Request::Lease { job: w.job, recipient: w.recipient, secrets, ttl_seconds: w.ttl_seconds }
        }
        "sign" => {
            let secret = named(line)?;
            let fields: SignFields = serde_json::from_slice(line)?;
            let missing = |field: &str| serde_json::Error::custom(format!("missing field `{field}`"));
            // A cancel (#7491) is the one transaction the vault builds for it: nothing a caller
            // could point at a recipient, a token or an amount, nor another chain's terms, is
            // taken, so none may be sent. `wallet::check_cancel` refuses one that names any
            // (`extra`), with its own message.
            if fields.cancel {
                let extra = [
                    ("to", fields.to.is_some()),
                    ("token", fields.token.is_some()),
                    ("amount", fields.amount.is_some()),
                    ("recent_blockhash", fields.recent_blockhash.is_some()),
                    ("compute_unit_limit", fields.compute_unit_limit.is_some()),
                    ("compute_unit_price", fields.compute_unit_price.is_some()),
                    ("create_recipient_account", fields.create_recipient_account.is_some()),
                    ("ref_block_num", fields.ref_block_num.is_some()),
                    ("ref_block_id", fields.ref_block_id.is_some()),
                    ("timestamp", fields.timestamp.is_some()),
                    ("expiration", fields.expiration.is_some()),
                    ("fee_limit", fields.fee_limit.is_some()),
                ]
                .into_iter()
                .filter_map(|(field, given)| given.then_some(field))
                .collect();
                return Ok(Request::SignCancel {
                    secret,
                    chain: fields.chain,
                    extra,
                    gas_limit: fields.gas_limit,
                    nonce: fields.nonce.ok_or_else(|| missing("nonce"))?,
                    max_fee_per_gas: fields.max_fee_per_gas.ok_or_else(|| missing("max_fee_per_gas"))?,
                    max_priority_fee_per_gas: fields.max_priority_fee_per_gas.ok_or_else(|| missing("max_priority_fee_per_gas"))?,
                    ladder: fields.ladder.unwrap_or(0),
                    ladder_max_fee_per_gas: fields.ladder_max_fee_per_gas,
                    on_behalf_of: fields.on_behalf_of,
                });
            }
            for (field, given) in [("token", &fields.token), ("to", &fields.to), ("amount", &fields.amount)] {
                if given.is_none() {
                    return Err(missing(field));
                }
            }
            Request::Sign { secret, fields }
        }
        "fill" => {
            let w: FillWire = serde_json::from_slice(line)?;
            Request::Fill {
                secret: secret_ref(w.name, w.id)?,
                origin: w.origin,
                fields: w.fields,
                engine: w.engine,
                tab: w.tab,
                on_behalf_of: w.on_behalf_of,
            }
        }
        "update_login" => {
            let w: UpdateLoginWire = serde_json::from_slice(line)?;
            Request::UpdateLogin { secret: secret_ref(w.name, w.id)?, username: w.username, site: w.site }
        }
        "generate_login" => {
            let w: GenerateLoginWire = serde_json::from_slice(line)?;
            Request::GenerateLogin { name: w.name, site: w.site, username: w.username, length: w.length }
        }
        "wallet_create" => {
            let w: WalletCreateWire = serde_json::from_slice(line)?;
            Request::WalletCreate { name: w.name, chain: w.chain, caps: w.caps, recovery_key: w.recovery_key }
        }
        "wallet_caps" => {
            let secret = named(line)?;
            let w: WalletCapsWire = serde_json::from_slice(line)?;
            Request::WalletCaps { secret, caps: w.caps, recovery_key: w.recovery_key }
        }
        "audit" => Request::Audit { all: serde_json::from_slice::<AuditWire>(line)?.all },
        "add" => {
            let w: AddWire = serde_json::from_slice(line)?;
            Request::Add {
                name: w.name,
                kind: w.kind,
                site: w.site,
                rule: w.rule,
                username: w.username,
                app: w.app,
                leasable: w.leasable,
                value: w.value,
            }
        }
        "confirm-kit" => Request::ConfirmKit { recovery_key: serde_json::from_slice::<ConfirmKitWire>(line)?.recovery_key },
        "reset" => Request::Reset { recovery_key: serde_json::from_slice::<ResetWire>(line)?.recovery_key },
        "restore" => {
            let w: RestoreWire = serde_json::from_slice(line)?;
            Request::Restore { recovery_key: w.recovery_key, backup_len: w.backup_len, source: w.source }
        }
        "mirror-report" => {
            let w: MirrorReportWire = serde_json::from_slice(line)?;
            Request::MirrorReport {
                ok: w.ok,
                newest_file: w.newest_file,
                newest_generation: w.newest_generation,
                copied: w.copied,
                already_there: w.already_there,
                detail: w.detail,
            }
        }
        other => return Err(serde_json::Error::custom(format!("unknown op {other:?}"))),
    })
}

/// The requests that carry a secret, as the command-line tool sends them (inside `Outgoing`).
/// Built only in `client`, which checks the daemon first (R27).
#[derive(Serialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub(crate) enum SecretRequest<'a> {
    Add {
        name: &'a str,
        kind: Kind,
        site: &'a str,
        rule: Option<&'a RuleInput>,
        username: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        app: Option<&'a str>,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        leasable: bool,
        #[serde(serialize_with = "secret_bytes::serialize_ref")]
        value: &'a SecretValue,
    },
    ConfirmKit {
        #[serde(serialize_with = "secret_bytes::serialize_ref")]
        recovery_key: &'a SecretValue,
    },
    #[serde(rename = "wallet_create")]
    WalletCreate {
        name: &'a str,
        chain: &'a str,
        caps: &'a crate::wallet::Caps,
        #[serde(serialize_with = "secret_bytes::serialize_ref")]
        recovery_key: &'a SecretValue,
    },
    #[serde(rename = "wallet_caps")]
    WalletCaps {
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<&'a str>,
        caps: &'a crate::wallet::Caps,
        #[serde(serialize_with = "secret_bytes::serialize_ref")]
        recovery_key: &'a SecretValue,
    },
    Reset {
        #[serde(serialize_with = "secret_bytes::serialize_opt_ref")]
        recovery_key: Option<&'a SecretValue>,
    },
    Restore {
        #[serde(serialize_with = "secret_bytes::serialize_ref")]
        recovery_key: &'a SecretValue,
        backup_len: Option<usize>,
        source: Option<String>,
    },
}

/// A request as the command-line tool sends it: its own fields, plus the protocol version and a
/// request id. Serializing it writes straight into the caller's (wiped) buffer; flattening
/// keeps no copy of its own.
#[derive(Serialize)]
pub(crate) struct Outgoing<'a, T: Serialize> {
    #[serde(flatten)]
    pub request: &'a T,
    pub protocol: u32,
    pub request_id: &'a str,
}

#[derive(Serialize, Deserialize)]
pub struct OkReply {
    pub ok: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ListReply {
    pub ok: bool,
    pub secrets: Vec<SecretSummary>,
}

#[derive(Serialize)]
pub struct TotpReply {
    pub ok: bool,
    pub id: String,
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

/// The head of a streamed reply: the upstream's status and headers (hop-by-hop ones left out).
#[derive(Serialize)]
pub struct StreamHead {
    pub ok: bool,
    pub status: u16,
    pub headers: Vec<[String; 2]>,
}

/// The line after a streamed reply's last chunk.
#[derive(Serialize)]
pub struct StreamTrailer {
    pub ok: bool,
    /// `complete`, or why it was cut short: `idle_timeout`, `upstream_failed`, `echo_blocked`.
    pub end: &'static str,
    /// Body bytes sent to the caller.
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// One credential's health, by name only (R4): whether its token works, has expired or was
/// refused, so the host can tell the person to sign in again.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CredentialHealth {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub version: u64,
    pub state: HealthState,
    /// When the state was last seen (RFC 3339), null for `unknown`.
    pub checked_at: Option<String>,
    /// The upstream status that said so.
    pub status: Option<u16>,
    /// Why, when the upstream said more than its status: a Google AI login refused under Google's
    /// Terms of Service. A fixed sentence, never the upstream's own text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `never`: the vault doesn't renew this kind (a Claude plan's token lasts a year; a new
    /// sign-in replaces it). `by_vault`: the vault renews it before it expires and on an auth
    /// error. `awaiting_claim`: an imported login the host's daemon may still be renewing; the
    /// vault uses it but renews it only after `claim_refresh`.
    pub refresh: String,
    pub expires_at: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct HealthReply {
    pub ok: bool,
    pub credentials: Vec<CredentialHealth>,
}

#[derive(Serialize, Deserialize)]
pub struct AddSealedReply {
    pub ok: bool,
    pub secret: SecretSummary,
    /// It replaced the value of a secret already stored under the name.
    pub replaced: bool,
    pub backup: BackupStatus,
}

/// One plan of an `import_plan`, by name only.
#[derive(Serialize, Deserialize)]
pub struct ImportedPlan {
    pub name: String,
    /// `done` (added, or a different value replaced), `unchanged` (already there with this
    /// value) or `failed`.
    pub result: String,
    /// The version the plan has now (for done and unchanged).
    pub version: Option<u64>,
    /// For failed: the error code and message.
    pub error: Option<String>,
    pub message: Option<String>,
}

/// One login of an `import_login`, by name only.
#[derive(Serialize, Deserialize)]
pub struct ImportedLogin {
    pub name: String,
    pub kind: Kind,
    /// `done` (added, or a different auth.json replaced an unclaimed one), `unchanged` (the
    /// auth.json the last import stored) or `failed`.
    pub result: String,
    /// The version it has now (for done and unchanged): what `claim_refresh` takes.
    pub version: Option<u64>,
    /// Whether the vault alone renews it already.
    pub claimed: bool,
    pub error: Option<String>,
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ImportLoginReply {
    pub ok: bool,
    pub logins: Vec<ImportedLogin>,
    /// The backup of the change, or null when nothing changed.
    pub backup: Option<BackupStatus>,
}

#[derive(Serialize, Deserialize)]
pub struct ClaimReply {
    pub ok: bool,
    pub secret: SecretSummary,
    /// True from now on: only the vault renews it.
    pub claimed: bool,
    /// It was claimed before this request; nothing changed.
    pub already: bool,
    /// The backup of the change, or null when nothing changed.
    pub backup: Option<BackupStatus>,
}

/// `sign`'s fields as the caller sent them: the transfer, and the terms of the wallet's chain
/// (`wallet::SignArgs` says which). Structured fields only; there is none for raw bytes.
#[derive(Deserialize, Default, Debug)]
pub struct SignFields {
    pub chain: String,
    /// A cancel (#7491): no `to`, `token` or `amount`, which a payment needs.
    #[serde(default)]
    pub cancel: bool,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub on_behalf_of: Option<String>,
    #[serde(default)]
    pub nonce: Option<u64>,
    #[serde(default)]
    pub gas_limit: Option<u64>,
    #[serde(default)]
    pub max_fee_per_gas: Option<u64>,
    #[serde(default)]
    pub max_priority_fee_per_gas: Option<u64>,
    #[serde(default)]
    pub ladder: Option<usize>,
    #[serde(default)]
    pub ladder_max_fee_per_gas: Option<u64>,
    #[serde(default)]
    pub recent_blockhash: Option<String>,
    #[serde(default)]
    pub compute_unit_limit: Option<u32>,
    #[serde(default)]
    pub compute_unit_price: Option<u64>,
    #[serde(default)]
    pub create_recipient_account: Option<bool>,
    #[serde(default)]
    pub ref_block_num: Option<u64>,
    #[serde(default)]
    pub ref_block_id: Option<String>,
    #[serde(default)]
    pub timestamp: Option<u64>,
    #[serde(default)]
    pub expiration: Option<u64>,
    #[serde(default)]
    pub fee_limit: Option<u64>,
}

impl SignFields {
    pub fn args(&self) -> crate::wallet::SignArgs<'_> {
        crate::wallet::SignArgs {
            chain: &self.chain,
            token: self.token.as_deref().unwrap_or(""),
            to: self.to.as_deref().unwrap_or(""),
            amount: self.amount.as_deref().unwrap_or(""),
            on_behalf_of: self.on_behalf_of.as_deref(),
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            ladder: self.ladder,
            ladder_max_fee_per_gas: self.ladder_max_fee_per_gas,
            recent_blockhash: self.recent_blockhash.as_deref(),
            compute_unit_limit: self.compute_unit_limit,
            compute_unit_price: self.compute_unit_price,
            create_recipient_account: self.create_recipient_account,
            ref_block_num: self.ref_block_num,
            ref_block_id: self.ref_block_id.as_deref(),
            timestamp: self.timestamp,
            expiration: self.expiration,
            fee_limit: self.fee_limit,
        }
    }
}

/// A wallet made or its caps changed.
#[derive(Serialize, Deserialize)]
pub struct WalletReply {
    pub ok: bool,
    pub secret: SecretSummary,
    pub backup: BackupStatus,
}

/// One signed transaction: its bytes in the chain's broadcast form and its id. Ethereum: `0x` hex
/// for `eth_sendRawTransaction`, the `0x` hash, and its fees. Solana: base64 for `sendTransaction`
/// (`"encoding":"base64"`) and the base58 signature. Tron: hex of the whole `Transaction` for
/// `/wallet/broadcasthex`, the txid, and `raw_data_hex` for `/wallet/broadcasttransaction`.
#[derive(Serialize, Deserialize, Clone)]
pub struct SignedTx {
    pub raw: String,
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_data_hex: Option<String>,
}

/// `sign`'s answer: the transfer as the vault built it, the first transaction, the ladder in
/// rising order, and what it counted against the caps. Signatures, never a key (R4).
#[derive(Serialize, Deserialize)]
pub struct SignReply {
    pub ok: bool,
    pub id: String,
    pub name: String,
    pub chain: crate::wallet::Chain,
    /// Ethereum: the chain id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    /// The wallet's address (EIP-55 mixed case on Ethereum).
    pub from: String,
    /// The recipient's wallet, canonical.
    pub to: String,
    pub token: crate::wallet::Token,
    /// The token's contract the transaction calls (on Solana, its mint).
    pub contract: String,
    pub amount: String,
    /// Ethereum: the nonce and gas limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    /// Solana: the token accounts the vault derived (the wallet's, the recipient's), the blockhash
    /// the transaction lives by, and whether it creates the recipient's token account if missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_token_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_token_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_blockhash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creates_recipient_account: Option<bool>,
    /// Tron: when the transaction stops being valid (Unix ms), and its fee_limit (sun).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_limit: Option<u64>,
    pub signed: SignedTx,
    /// Ethereum: the same transfer at rising fees, in rising order. Empty on Solana and Tron.
    pub ladder: Vec<SignedTx>,
    /// The most any of these transactions could cost in fees, in `fee_unit`.
    pub worst_fee: u64,
    pub fee_unit: String,
    /// The same payment was signed in the last day (Ethereum: the same transfer at this nonce;
    /// Solana and Tron: the very same transaction): no amount counted again.
    pub replacement: bool,
    pub counted_micros: u64,
    pub counted_fees: u64,
    /// The wallet's caps, and what the last 24 hours count against them now, this payment in.
    pub caps: crate::wallet::Caps,
    pub spent_today_micros: u64,
    pub fees_today: u64,
    /// Ethereum only, under the names #7440 gave them: `worst_fee`, `counted_fees`, `fees_today`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worst_fee_wei: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counted_fees_wei: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fees_today_wei: Option<u64>,
    pub backup: BackupStatus,
}

/// `sign`'s answer to a cancel (#7491): the cancel as the vault built it (0 ETH from the wallet
/// to itself, 21,000 gas, no data), its first transaction, its ladder in rising order, and what it
/// counted against the daily fee cap. Signatures, never a key (R4).
#[derive(Serialize, Deserialize)]
pub struct CancelReply {
    pub ok: bool,
    /// Always true: tells this answer from a payment's.
    pub cancel: bool,
    pub id: String,
    pub name: String,
    pub chain: crate::wallet::Chain,
    pub chain_id: u64,
    /// The wallet's address, EIP-55 mixed case: the cancel's sender and its recipient.
    pub from: String,
    pub to: String,
    pub nonce: u64,
    pub gas_limit: u64,
    /// The payments signed at this nonce in the last day that it cancels.
    pub cancels: Vec<String>,
    pub signed: SignedTx,
    pub ladder: Vec<SignedTx>,
    /// The most any of these transactions could burn in fees: 21,000 gas at the top rung.
    pub worst_fee_wei: u64,
    /// What it raised the nonce's worst-case fee by, counted against `daily_fees`.
    pub counted_fees_wei: u64,
    pub caps: crate::wallet::Caps,
    pub spent_today_micros: u64,
    pub fees_today_wei: u64,
    pub backup: BackupStatus,
}

/// One app secret of a lease: its value sealed to the job's key, as base64 of an age file.
#[derive(Serialize, Deserialize)]
pub struct LeasedSecret {
    pub name: String,
    pub id: String,
    pub sealed_base64: String,
}

/// A lease's answer: ciphertext only (R4).
#[derive(Serialize, Deserialize)]
pub struct LeaseReply {
    pub ok: bool,
    pub sealed: Vec<LeasedSecret>,
    /// The names (or ids) the vault holds nothing under.
    pub missing: Vec<String>,
    /// When the lease ends, as sealed inside each value (RFC 3339).
    pub expires_at: String,
    pub job: String,
}

#[derive(Serialize, Deserialize)]
pub struct ImportReply {
    pub ok: bool,
    pub plans: Vec<ImportedPlan>,
    /// The backup of the change, or null when nothing changed.
    pub backup: Option<BackupStatus>,
}

/// What `vault status` shows from the daemon's side. Information only; no values.
#[derive(Serialize, Deserialize)]
pub struct StatusReply {
    pub ok: bool,
    pub version: String,
    /// The vault-file format this daemon writes.
    #[serde(default)]
    pub format: u32,
    pub pid: u32,
    pub uid: u32,
    pub key_protection: String,
    /// Which key file the daemon opened the vault with at its start (`keyprotect::loaded_from`):
    /// `sealed`, `pending`, `plain`, or null (no vault, or a daemon too old to say).
    #[serde(default)]
    pub key_source: Option<String>,
    pub local_backups: String,
    pub restore_point: bool,
    pub vault: Option<OpenedStatus>,
    pub mirror: Option<MirrorState>,
}

#[derive(Serialize, Deserialize)]
pub struct OpenedStatus {
    /// This copy of the vault; a restore makes a new one.
    pub vault_id: String,
    /// The vault's stable identity, the same after every restore (`model::vault_identity`).
    #[serde(default)]
    pub vault_identity: String,
    /// The vault file's format.
    #[serde(default)]
    pub format: u32,
    pub created_at: String,
    pub recovery_fingerprint: String,
    pub kit_confirmed: bool,
    pub kit_path: Option<String>,
    pub mirror_dir: String,
    pub generation: u64,
    pub secrets: usize,
    pub by_kind: Vec<(Kind, usize)>,
    pub last_backup: Option<BackupStatus>,
    /// The intake public key (an age X25519 recipient), for sealing values to this vault (R40).
    #[serde(default)]
    pub intake_recipient: Option<String>,
    /// The audit log's line count when its chain is intact, or what is wrong with it.
    pub audit_lines: Option<usize>,
    /// How many files the chain runs through: `audit.log` and the rotated `audit.log.<n>`.
    #[serde(default)]
    pub audit_files: Option<usize>,
    pub audit_problem: Option<String>,
    pub recent_changes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AuditReply {
    pub ok: bool,
    pub total: usize,
    pub lines: Vec<AuditLine>,
    pub problem: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AddReply {
    pub ok: bool,
    pub secret: SecretSummary,
    pub backup: BackupStatus,
}

#[derive(Serialize, Deserialize)]
pub struct RenameReply {
    pub ok: bool,
    pub secret: SecretSummary,
    pub backup: BackupStatus,
}

/// `update_login`'s answer: the login as it is now and what changed. No backup when nothing did.
#[derive(Serialize, Deserialize)]
pub struct UpdateLoginReply {
    pub ok: bool,
    pub secret: SecretSummary,
    pub changed: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupStatus>,
}

#[derive(Serialize, Deserialize)]
pub struct BackupReply {
    pub ok: bool,
    pub backup: BackupStatus,
}

#[derive(Serialize, Deserialize)]
pub struct ConfirmKitReply {
    pub ok: bool,
    /// The kit file `vault install` wrote, for the command-line tool to delete: it is the
    /// owner's file, which the daemon's account can't touch.
    pub kit_path: Option<String>,
    pub backup: BackupStatus,
}

#[derive(Serialize, Deserialize)]
pub struct ResetReply {
    pub ok: bool,
    /// True when the vault never held a secret and went without the recovery key.
    pub unused: bool,
    pub newest_file: Option<String>,
    pub kit_path: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct RestoreReply {
    pub ok: bool,
    pub vault_id: String,
    #[serde(default)]
    pub vault_identity: String,
    pub from_vault_id: String,
    #[serde(default)]
    pub from_format: u32,
    pub from_generation: u64,
    pub secrets: Vec<SecretSummary>,
    pub backup: BackupStatus,
}

/// The check of the newest backup that the daemon makes for `verify-backup`. No values.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BackupCheck {
    pub file: String,
    pub generation: u64,
    pub written_at: String,
    pub secrets: usize,
    pub matches_vault: bool,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyBackupReply {
    pub ok: bool,
    pub check: BackupCheck,
}

/// The newest backup as it sits in the folder: age ciphertext, readable only with the recovery
/// key or the vault's own check key.
#[derive(Serialize, Deserialize)]
pub struct ReadBackupReply {
    pub ok: bool,
    pub file: String,
    pub data_base64: String,
}

/// What the mirror needs: where the backups are, and where they go.
#[derive(Serialize, Deserialize)]
pub struct MirrorPlanReply {
    pub ok: bool,
    pub local_dir: String,
    pub mirror_dir: String,
    pub vault_id: String,
    pub generation: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorReply {
    pub ok: bool,
    pub error: String,
    pub message: String,
    /// `not_leasable`: the secrets refused, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
}

impl ErrorReply {
    pub fn from(error: &VaultError) -> Self {
        let names = match error {
            VaultError::NotLeasable(names) => Some(names.clone()),
            _ => None,
        };
        ErrorReply { ok: false, error: error.code().into(), message: error.to_string(), names }
    }
}
