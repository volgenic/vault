//! The local socket's protocol: one JSON request per connection, one JSON reply line back.
//!
//! The daemon accepts connections only from the owner's user ID and root (R22). Every agent on
//! the Mac runs as the owner, so every request here is open to every agent.
//!
//! For agents:
//!   {"op":"list"}
//!   {"op":"totp","name":"github-2fa"}
//!   {"op":"proxy","name":"openai","method":"GET","path":"/v1/models",
//!    "headers":{"accept":"application/json"},"body":"..."}            (or "body_base64")
//!
//! For the command-line tool (R13: only the daemon changes the vault; R26):
//!   status, audit, add, delete, confirm-kit, reset, restore,
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
//! belong to the vault's own account (R22, R27).
//!
//! No reply type has a field that could carry a secret value (R4): `SecretValue` doesn't
//! implement `Serialize`, so it can't appear in any of them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::audit::AuditLine;
use crate::error::VaultError;
use crate::model::{BackupStatus, Kind, MirrorState, SecretSummary, secret_bytes};
use crate::secret::SecretValue;

pub const MAX_REQUEST_LINE: usize = 2 * 1024 * 1024;

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
    Status,
    Audit {
        #[serde(default)]
        all: bool,
    },
    Add {
        name: String,
        kind: Kind,
        site: String,
        #[serde(default)]
        rule: Option<RuleInput>,
        #[serde(default)]
        username: Option<String>,
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        value: SecretValue,
    },
    Delete {
        name: String,
    },
    ConfirmKit {
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        recovery_key: SecretValue,
    },
    Reset {
        #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
        recovery_key: Option<SecretValue>,
    },
    Restore {
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        recovery_key: SecretValue,
        /// The size of a backup file the person named (`vault restore FILE`). Its bytes follow
        /// the request line as they are, up to `backup::MAX_BACKUP_BYTES`. Without it, the
        /// restore point `vault reset` kept.
        #[serde(default)]
        backup_len: Option<usize>,
        #[serde(default)]
        source: Option<String>,
    },
    Backup,
    VerifyBackup,
    ReadBackup,
    MirrorPlan,
    MirrorReport {
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
    },
}

/// The requests that carry a secret, as the command-line tool sends them. Built only in
/// `client`, which checks the daemon first (R27).
#[derive(Serialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub(crate) enum SecretRequest<'a> {
    Add {
        name: &'a str,
        kind: Kind,
        site: &'a str,
        rule: Option<&'a RuleInput>,
        username: Option<&'a str>,
        #[serde(serialize_with = "secret_bytes::serialize_ref")]
        value: &'a SecretValue,
    },
    ConfirmKit {
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

/// What `vault status` shows from the daemon's side. Information only; no values.
#[derive(Serialize, Deserialize)]
pub struct StatusReply {
    pub ok: bool,
    pub version: String,
    pub pid: u32,
    pub uid: u32,
    pub key_protection: String,
    pub local_backups: String,
    pub restore_point: bool,
    pub vault: Option<OpenedStatus>,
    pub mirror: Option<MirrorState>,
}

#[derive(Serialize, Deserialize)]
pub struct OpenedStatus {
    pub vault_id: String,
    pub created_at: String,
    pub recovery_fingerprint: String,
    pub kit_confirmed: bool,
    pub kit_path: Option<String>,
    pub mirror_dir: String,
    pub generation: u64,
    pub secrets: usize,
    pub by_kind: Vec<(Kind, usize)>,
    pub last_backup: Option<BackupStatus>,
    /// The audit log's line count when its chain is intact, or what is wrong with it.
    pub audit_lines: Option<usize>,
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
pub struct BackupReply {
    pub ok: bool,
    pub backup: BackupStatus,
}

#[derive(Serialize, Deserialize)]
pub struct ConfirmKitReply {
    pub ok: bool,
    /// The kit file `install-system` wrote, for the command-line tool to delete: it is the
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
    pub from_vault_id: String,
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
}

impl ErrorReply {
    pub fn from(error: &VaultError) -> Self {
        ErrorReply { ok: false, error: error.code().into(), message: error.to_string() }
    }
}
