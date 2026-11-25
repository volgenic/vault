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

/// The kinds of secret. Each has exactly one use (R5). The kinds that make HTTPS calls for a
/// caller with a credential of their own (a Claude plan today) are described in `kinds`.
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
    /// One Claude plan's token (a `claude setup-token` token): used only by `stream`, only to the
    /// hosts, methods and paths `kinds::CLAUDE_PLAN` allows, in the header it names.
    #[serde(rename = "claude_plan", alias = "claude-plan")]
    ClaudePlan,
    /// A Codex login (a ChatGPT sign-in: access, refresh and id tokens and the account id), used
    /// only by `stream` as `kinds::CODEX_LOGIN` allows, and renewed only by the vault (#7380).
    #[serde(rename = "codex_login")]
    CodexLogin,
    /// A Grok Build login (a grok.com sign-in), as `kinds::GROK_LOGIN` allows, renewed only by
    /// the vault.
    #[serde(rename = "grok_login")]
    GrokLogin,
    /// A Google AI Pro or Ultra login (a Google sign-in made by Antigravity's `agy`), as
    /// `kinds::GOOGLE_AI_LOGIN` allows, renewed only by the vault (#8147).
    #[serde(rename = "google_ai_login")]
    GoogleAiLogin,
    /// A person's real details (name, address, birthday, phone), filled per field (`details`,
    /// #7435). Stored and listed only, for now: no request gives a value back.
    #[serde(rename = "personal_details")]
    PersonalDetails,
    /// One of an application's build and deploy secrets (an npm token, a database URL), stored
    /// for the application it names (#7446). Its only use is `lease`: sealed to one build's own
    /// key, for at most a day, and only when it was added as leasable (`lease`). No other request
    /// uses it or gives its value back.
    #[serde(rename = "app_secret")]
    AppSecret,
    /// A wallet's private key, made by the vault itself and never given out, not even sealed
    /// (#7440). Its only use is `sign`: a token transfer the vault builds from structured fields,
    /// within the caps the person set (`wallet`). No request adds or replaces one with a value.
    #[serde(rename = "wallet")]
    Wallet,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::ApiKey => "api-key",
            Kind::Login => "login",
            Kind::TwoFactor => "2fa",
            Kind::ClaudePlan => "claude_plan",
            Kind::CodexLogin => "codex_login",
            Kind::GrokLogin => "grok_login",
            Kind::GoogleAiLogin => "google_ai_login",
            Kind::PersonalDetails => "personal_details",
            Kind::AppSecret => "app_secret",
            Kind::Wallet => "wallet",
        }
    }

    /// Every kind, in the order listings count them.
    pub const ALL: [Kind; 10] = [
        Kind::ApiKey,
        Kind::Login,
        Kind::TwoFactor,
        Kind::ClaudePlan,
        Kind::CodexLogin,
        Kind::GrokLogin,
        Kind::GoogleAiLogin,
        Kind::PersonalDetails,
        Kind::AppSecret,
        Kind::Wallet,
    ];

    /// The site a secret of this kind gets when none is given, for a kind not tied to one site.
    pub fn default_site(self) -> Option<&'static str> {
        match self {
            Kind::PersonalDetails => Some(crate::details::DEFAULT_SITE),
            kind => crate::kinds::spec(kind).map(|spec| spec.default_site),
        }
    }
}

/// What a listing shows: the secret's stable id and version, name, kind and site, nothing else.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretSummary {
    /// Random, given when the secret is added; it never changes, through renames and restores.
    /// Absent only in a reply from a daemon older than format 2.
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub site: String,
    /// 1 when added, plus one for every change to this secret (a rename, today).
    #[serde(default)]
    pub version: u64,
    /// Personal details only: which fields are filled (`details::FIELDS`), never their values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
    /// An app secret only: the application it belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// An app secret only: whether it may be leased to builds (`lease`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leasable: Option<bool>,
    /// A wallet only: its chain, address and caps, and what it signed in the last day. Never
    /// its key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<WalletSummary>,
    /// An API key only: its rule as a person reads it (`ProxyRule::describe`): where the key
    /// may go, and whether in a header or a query parameter. Never the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

/// What a listing shows of a wallet.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WalletSummary {
    pub chain: crate::wallet::Chain,
    /// Canonical: lower-case `0x` hex on Ethereum, base58 on Solana, `T...` on Tron.
    pub address: String,
    /// The address to show a person: EIP-55 mixed case on Ethereum, `address` elsewhere.
    pub checksummed: String,
    pub caps: crate::wallet::Caps,
    /// What the last 24 hours' payments count against the caps.
    pub spent_today_micros: u64,
    /// Their worst-case fees, in `fee_unit` (wei, lamports or sun).
    pub fees_today: u64,
    pub fee_unit: String,
    /// Ethereum only: `fees_today`, under the name #7440 gave it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fees_today_wei: Option<u64>,
}

/// One stored secret.
#[derive(Serialize, Deserialize)]
pub(crate) struct Record {
    /// The secret's stable id: 16 random bytes as hex (`new_random_id`). Format 1 had none;
    /// `migrate` gives every record one.
    #[serde(default)]
    pub id: String,
    /// Starts at 1 and goes up by one with every change to this record.
    #[serde(default)]
    pub version: u64,
    pub name: String,
    pub kind: Kind,
    pub site: String,
    pub created_at: String,
    /// When the record last changed (its creation, for a record never changed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<ProxyRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpParams>,
    /// When the stored credential stops working, in Unix seconds, for a kind whose refresher
    /// renews it before then (`kinds::Refresher`). None for a kind without one (a Claude plan).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// For a kind the vault renews (a Codex or Grok login): whose it is to renew (#7380).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handover: Option<Handover>,
    /// For personal details: the names of the filled fields, so a listing can say which a form
    /// may use without opening the value (#7435).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
    /// For an app secret: the application it belongs to (#7446).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// For an app secret: it may be leased to builds, as said when it was added. Without it,
    /// `lease` refuses the secret (`not_leasable`). Nothing changes it after the add.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leasable: Option<bool>,
    /// For a wallet: its chain, address, caps and last day's payments (#7440). The key itself is
    /// the record's value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<crate::wallet::WalletInfo>,
    #[serde(with = "secret_bytes")]
    pub value: SecretValue,
}

/// Who renews a login the vault holds. A login imported from the host's `auth.json` stays the
/// host daemon's to renew until the daemon says it has stopped (`claim_refresh`): until then the
/// vault never renews it, since renewing retires the refresh token the daemon still holds. A login
/// that arrives any other way (a new sign-in, sealed) is the vault's from the start.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Handover {
    /// The vault renews it; nothing else may.
    pub claimed: bool,
    /// When it was claimed, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<String>,
    /// `logins::digest` of the login as the last import stored it, so the same `auth.json`
    /// imported again changes nothing, even after the vault renewed it. Inside the vault file
    /// only; never in a reply or the audit log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported: Option<String>,
}

impl Record {
    pub fn summary(&self) -> SecretSummary {
        SecretSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            kind: self.kind,
            site: self.site.clone(),
            version: self.version,
            fields: self.fields.clone(),
            app: self.app.clone(),
            leasable: if self.kind == Kind::AppSecret { Some(self.leasable == Some(true)) } else { None },
            rule: self.rule.as_ref().map(ProxyRule::describe),
            wallet: self.wallet.as_ref().map(|info| {
                let now = crate::now_unix();
                let (spent, fees) = info.spent(now);
                let family = info.chain.family();
                WalletSummary {
                    chain: info.chain,
                    address: info.address.clone(),
                    checksummed: info.display_address(),
                    caps: info.caps,
                    spent_today_micros: spent,
                    fees_today: fees,
                    fee_unit: family.fee_unit().to_string(),
                    fees_today_wei: (family == crate::wallet::Family::Evm).then_some(fees),
                }
            }),
        }
    }

    /// Whether `lease` may seal this record's value to a build: an app secret added as leasable.
    pub fn may_lease(&self) -> bool {
        self.kind == Kind::AppSecret && self.leasable == Some(true)
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
    /// The intake key: an age X25519 identity whose public half `vault status --json` shows, so a
    /// value typed in Volgenic's app can be sealed to this vault and carried by Volgenic's server
    /// without the server being able to read it (`add_sealed`, `intake`). Made at init, at a
    /// restore and when a format-2 vault is migrated; backups don't carry it, so a restored vault
    /// gets a new one. None only while a format-2 document is being migrated.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "secret_bytes_opt")]
    pub intake_identity: Option<SecretValue>,
    /// The audit chain's head at the last change (R29).
    pub audit_head: String,
    /// Increments on every change; numbers the backups.
    pub generation: u64,
    #[serde(default)]
    pub last_backup: Option<BackupStatus>,
    pub records: Vec<Record>,
}

/// The format this build writes, in the vault file and in backups.
///
/// - **1** (pull requests #2 to #4): records keyed by name only.
/// - **2**: every record has a random `id`, a `version` and an `updated_at`.
/// - **3**: the `claude_plan` kind, a record's `expires_at`, and the vault's intake key. An older
///   build can't read a Claude plan, so the format number tells it this file is newer instead
///   of letting it call the file damaged (R36).
/// - **4**: the `codex_login` and `grok_login` kinds and a record's `handover` (#7380).
/// - **5**: the `personal_details` kind and a record's `fields` (#7435).
/// - **6**: the `app_secret` kind and a record's `app` and `leasable` (#7446).
/// - **7**: the `wallet` kind and a record's `wallet` (#7440).
/// - **8**: Solana and Tron wallets, with their own fee caps, and a spend's `fee` (was `fee_wei`)
///   and `identity` (#7490).
/// - **9**: the `google_ai_login` kind (#8147).
/// - **10**: an API key's rule may put the key in a query parameter, `query_param` (#8940). An
///   older build would read such a rule as one with an empty header name, so the format number
///   tells it this file is newer instead.
pub(crate) const VAULT_FORMAT: u32 = 10;

/// Every format this build reads. Older ones are migrated to `VAULT_FORMAT` when read.
pub(crate) const READABLE_FORMATS: [u32; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

/// A secret as a request names it: by its name, or by its stable id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretRef {
    Name(String),
    Id(String),
}

impl SecretRef {
    /// How the audit log and errors show it.
    pub fn label(&self) -> String {
        match self {
            SecretRef::Name(name) => name.clone(),
            SecretRef::Id(id) => format!("id {id}"),
        }
    }

    pub fn not_found(&self) -> VaultError {
        VaultError::UnknownSecret(self.label())
    }
}

impl VaultDoc {
    pub fn find(&self, name: &str) -> Option<&Record> {
        self.records.iter().find(|record| record.name == name)
    }

    pub fn find_ref(&self, secret: &SecretRef) -> Option<&Record> {
        match secret {
            SecretRef::Name(name) => self.find(name),
            SecretRef::Id(id) => self.records.iter().find(|record| &record.id == id),
        }
    }

    pub fn summaries(&self) -> Vec<SecretSummary> {
        self.records.iter().map(Record::summary).collect()
    }
}

/// The vault's stable identity: the first 128 bits of the SHA-256 of its recovery public key,
/// as hex. The recovery key is made once, at install, and every restore keeps it (R16, R20), so
/// this survives restores and moves to another machine, and it never names a machine. Its
/// first 12 digits are the recovery-key fingerprint the kit and `vault status` show, so a
/// person can match the two by eye.
pub fn vault_identity(recovery_recipient: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(recovery_recipient.as_bytes())[..16])
}

/// Brings a document read in an older format up to `VAULT_FORMAT`: format 1 records get a
/// random id each (from `new_id`), version 1, and `updated_at` equal to `created_at`. Returns
/// how many records were given ids, or `None` when the document was already current. Pure apart
/// from `new_id`; the caller writes the result back (read old, write new).
pub(crate) fn migrate(
    doc: &mut VaultDoc,
    new_id: impl FnMut() -> Result<String, VaultError>,
) -> Result<Option<usize>, VaultError> {
    if doc.format == VAULT_FORMAT {
        return Ok(None);
    }
    if !READABLE_FORMATS.contains(&doc.format) {
        return Err(VaultError::NewerFormat(doc.format));
    }
    let given = migrate_records(&mut doc.records, new_id)?;
    doc.format = VAULT_FORMAT;
    Ok(Some(given))
}

/// Gives every record without an id one, with version 1: format-1 records, in a vault file or a
/// backup. Returns how many it gave.
pub(crate) fn migrate_records(
    records: &mut [Record],
    mut new_id: impl FnMut() -> Result<String, VaultError>,
) -> Result<usize, VaultError> {
    let mut given = 0;
    for record in records.iter_mut().filter(|record| record.id.is_empty()) {
        record.id = new_id()?;
        record.version = record.version.max(1);
        if record.updated_at.is_none() {
            record.updated_at = Some(record.created_at.clone());
        }
        given += 1;
    }
    Ok(given)
}

/// A format-2 document or backup must give every record a well-formed, unique id and a version
/// of at least 1; format 1 had neither. Anything else is damage.
pub(crate) fn check_ids(records: &[Record], format: u32) -> Result<(), VaultError> {
    if format < 2 {
        return Ok(());
    }
    let mut seen = std::collections::BTreeSet::new();
    for record in records {
        let well_formed = record.id.len() == 32 && record.id.bytes().all(|b| b.is_ascii_hexdigit());
        if !well_formed || record.version == 0 || !seen.insert(record.id.as_str()) {
            return Err(VaultError::VaultFileCorrupt);
        }
    }
    Ok(())
}

/// Gives a document without an intake key one (a format-2 vault being migrated). Returns whether
/// it made one. The caller writes the result back as a change of its own.
pub(crate) fn ensure_intake(doc: &mut VaultDoc) -> bool {
    if doc.intake_identity.is_some() {
        return false;
    }
    let (identity, _public) = crate::backup::new_identity();
    doc.intake_identity = Some(identity);
    true
}

/// Ids are 32 lower-case hex digits; anything else can't name a secret.
pub fn validate_id(id: &str) -> Result<(), VaultError> {
    let ok = id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if ok { Ok(()) } else { Err(VaultError::BadRequest("an id is 32 lower-case hex digits".into())) }
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

/// An application's name, as an app secret records it: 1 to 128 printable characters.
pub fn validate_app(app: &str) -> Result<(), VaultError> {
    let ok = !app.trim().is_empty()
        && app.chars().count() <= 128
        && app.chars().all(|c| !c.is_control() && c != '\u{7f}');
    if ok {
        Ok(())
    } else {
        Err(VaultError::InvalidSecret("the application must be 1 to 128 printable characters".into()))
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

/// `secret_bytes` for an optional value inside the vault file (the intake key).
pub(crate) mod secret_bytes_opt {
    use serde::{Deserializer, Serializer};

    use crate::secret::SecretValue;

    pub fn serialize<S: Serializer>(value: &Option<SecretValue>, serializer: S) -> Result<S::Ok, S::Error> {
        super::secret_bytes::serialize_opt_ref(&value.as_ref(), serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<SecretValue>, D::Error> {
        super::secret_bytes::deserialize_opt(deserializer)
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
