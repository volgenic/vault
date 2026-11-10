//! What the vault stores: secrets, their kinds and rules, and the vault document that holds
//! them. Plain data, no I/O.
//!
//! `Record` and `VaultDoc` serialize secret values (through `secret_bytes`) because they are
//! what gets encrypted into the vault file and the backups. They are crate-private: no reply
//! type and nothing in the command-line executable can reach them (R4). Replies use
//! `SecretSummary`, which has no field that could carry a value.

use serde::{Deserialize, Serialize};

use crate::error::VaultError;
use crate::rules::ProxyRule;
use crate::secret::SecretValue;
use crate::totp::TotpParams;

/// The three kinds of secret. Each has exactly one use (R5).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Used only by the proxy, in the auth header its rule names.
    #[serde(rename = "api-key")]
    ApiKey,
    /// Stored and listed only, in this item.
    #[serde(rename = "login")]
    Login,
    /// A 2FA (TOTP) seed: used only to make the current code.
    #[serde(rename = "2fa")]
    TwoFactor,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::ApiKey => "api-key",
            Kind::Login => "login",
            Kind::TwoFactor => "2fa",
        }
    }
}

/// What a listing shows: name, kind and site, nothing else (the item's "list" contract).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretSummary {
    pub name: String,
    pub kind: Kind,
    pub site: String,
}

/// One stored secret.
#[derive(Serialize, Deserialize)]
pub(crate) struct Record {
    pub name: String,
    pub kind: Kind,
    pub site: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<ProxyRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpParams>,
    #[serde(with = "secret_bytes")]
    pub value: SecretValue,
}

impl Record {
    pub fn summary(&self) -> SecretSummary {
        SecretSummary { name: self.name.clone(), kind: self.kind, site: self.site.clone() }
    }
}

/// The result of the last backup, as `vault status` shows it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BackupStatus {
    pub file: String,
    pub at: String,
    pub generation: u64,
    pub ok: bool,
    pub detail: String,
}

/// Everything in the vault file. Everything that decides what the vault trusts is here,
/// inside the encrypted, authenticated file (R15).
#[derive(Serialize, Deserialize)]
pub(crate) struct VaultDoc {
    pub format: u32,
    pub vault_id: String,
    pub created_at: String,
    /// The recovery public key (an age X25519 recipient). Set once at init (R16).
    pub recovery_recipient: String,
    pub kit_confirmed: bool,
    /// Where `init` wrote the kit, so `confirm-kit` can delete it.
    #[serde(default)]
    pub kit_path: Option<String>,
    /// Where `vault mirror` copies the backups (iCloud Drive by default). The daemon never opens
    /// it; the owner's mirror agent asks the daemon for it (R15, R32).
    pub mirror_dir: String,
    /// The check key: an age X25519 identity whose public half is the backups' second
    /// recipient, so the vault can decrypt each backup right after writing it (R18, R19).
    #[serde(with = "secret_bytes")]
    pub check_identity: SecretValue,
    /// The audit chain's head at the last change (R29).
    pub audit_head: String,
    /// Increments on every change; numbers the backups.
    pub generation: u64,
    #[serde(default)]
    pub last_backup: Option<BackupStatus>,
    pub records: Vec<Record>,
}

pub(crate) const VAULT_FORMAT: u32 = 1;

impl VaultDoc {
    pub fn find(&self, name: &str) -> Option<&Record> {
        self.records.iter().find(|record| record.name == name)
    }

    pub fn summaries(&self) -> Vec<SecretSummary> {
        self.records.iter().map(Record::summary).collect()
    }
}

/// What a backup holds: every secret and rule, plus enough to rebuild the vault (R18).
#[derive(Serialize, Deserialize)]
pub(crate) struct BackupPayload {
    pub format: u32,
    pub vault_id: String,
    pub written_at: String,
    pub generation: u64,
    pub recovery_recipient: String,
    pub audit_head: String,
    pub records: Vec<Record>,
}

/// What the owner's mirror agent last reported (R32). A status display, not proof: any program
/// running as the owner could send one.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MirrorState {
    /// When the daemon received the report.
    pub at: String,
    pub ok: bool,
    pub mirror_dir: String,
    /// The newest backup the mirror copied and checked, and its generation.
    pub newest_file: Option<String>,
    pub newest_generation: Option<u64>,
    pub copied: usize,
    pub already_there: usize,
    pub detail: String,
}

/// Names are 1 to 64 characters: letters, digits, dot, dash and underscore.
pub fn validate_name(name: &str) -> Result<(), VaultError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if ok { Ok(()) } else { Err(VaultError::InvalidName) }
}

/// Sites are short printable labels (a host name or a URL), shown in listings.
pub fn validate_site(site: &str) -> Result<(), VaultError> {
    let ok = !site.is_empty()
        && site.len() <= 200
        && site.chars().all(|c| !c.is_control() && c != '\u{7f}');
    if ok {
        Ok(())
    } else {
        Err(VaultError::InvalidSecret("the site must be 1 to 200 printable characters".into()))
    }
}

/// Usernames are 1 to 256 printable characters.
pub fn validate_username(username: &str) -> Result<(), VaultError> {
    let ok = !username.is_empty()
        && username.chars().count() <= 256
        && username.chars().all(|c| !c.is_control() && c != '\u{7f}');
    if ok {
        Ok(())
    } else {
        Err(VaultError::InvalidSecret("the username must be 1 to 256 printable characters".into()))
    }
}

/// Serializes a `SecretValue` as a byte array, only inside the encrypted vault file and backups.
/// This is the vault-file and backup call site of `expose` in R1.
pub(crate) mod secret_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::secret::SecretValue;

    pub fn serialize<S: Serializer>(value: &SecretValue, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value.expose())
    }

    /// Reads the bytes into a `crate::secret::WipingBuf`, never a plain `Vec` that would leave unwiped copies
    /// behind as it grows (R1).
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SecretValue, D::Error> {
        deserializer.deserialize_bytes(SecretVisitor)
    }

    struct SecretVisitor;

    impl<'de> serde::de::Visitor<'de> for SecretVisitor {
        type Value = SecretValue;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a byte array")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<SecretValue, A::Error> {
            let mut buf = crate::secret::WipingBuf::with_capacity(seq.size_hint().unwrap_or(0).clamp(64, 1 << 20));
            while let Some(byte) = seq.next_element::<u8>()? {
                buf.push(byte);
            }
            Ok(buf.into_secret())
        }

        fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<SecretValue, E> {
            let mut buf = crate::secret::WipingBuf::with_capacity(value.len());
            buf.extend_from_slice(value);
            Ok(buf.into_secret())
        }
    }

    /// For a request field that borrows the value: the client's call site of `expose` in R1,
    /// sending a typed value or recovery key to the verified daemon (R27).
    pub fn serialize_ref<S: Serializer>(value: &&SecretValue, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value.expose())
    }

    pub fn serialize_opt_ref<S: Serializer>(value: &Option<&SecretValue>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&Bytes(value.expose())),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize_opt<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<SecretValue>, D::Error> {
        struct Wrapped(SecretValue);
        impl<'de> Deserialize<'de> for Wrapped {
            fn deserialize<D2: Deserializer<'de>>(deserializer: D2) -> Result<Self, D2::Error> {
                super::secret_bytes::deserialize(deserializer).map(Wrapped)
            }
        }
        Ok(Option::<Wrapped>::deserialize(deserializer)?.map(|wrapped| wrapped.0))
    }

    struct Bytes<'a>(&'a [u8]);

    impl serde::Serialize for Bytes<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.0)
        }
    }
}
