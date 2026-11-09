//! The vault's errors: a closed list of codes (rule R2). None carries text taken from a secret;
//! the few that carry text carry names, paths or rule fields the caller supplied.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    UnsupportedPlatform,
    SecureEnclave,
    Keychain,
    KeyProtection,
    Random,
    AlreadyInitialized,
    NotInitialized,
    AutoLoginOn,
    NoSecureEnclave,
    KitNotConfirmed,
    KitAlreadyConfirmed,
    WrongRecoveryKey,
    VaultFileCorrupt,
    VaultFileUnreadable(String),
    UnsafeVaultFolder(String),
    Io(String),
    UnknownSecret(String),
    NameTaken(String),
    InvalidName,
    WrongKind,
    InvalidRule(String),
    InvalidSecret(String),
    BackupFailed(String),
    BackupMismatch,
    NoBackup,
    BadRequest(String),
    RuleMismatch(String),
    HeaderNotAllowed(String),
    UpstreamFailed(String),
    EncodedReplyRefused,
    ReplyTooLarge,
    EchoBlocked,
    Busy,
    AuditChainBroken(usize),
}

impl VaultError {
    /// A short stable code for replies on the socket and for the audit log.
    pub fn code(&self) -> &'static str {
        use VaultError::*;
        match self {
            UnsupportedPlatform => "unsupported_platform",
            SecureEnclave => "secure_enclave_error",
            Keychain => "keychain_error",
            KeyProtection => "key_protection_error",
            Random => "random_error",
            AlreadyInitialized => "already_initialized",
            NotInitialized => "not_initialized",
            AutoLoginOn => "auto_login_on",
            NoSecureEnclave => "no_secure_enclave",
            KitNotConfirmed => "kit_not_confirmed",
            KitAlreadyConfirmed => "kit_already_confirmed",
            WrongRecoveryKey => "wrong_recovery_key",
            VaultFileCorrupt => "vault_file_corrupt",
            VaultFileUnreadable(_) => "vault_file_unreadable",
            UnsafeVaultFolder(_) => "unsafe_vault_folder",
            Io(_) => "io_error",
            UnknownSecret(_) => "unknown_secret",
            NameTaken(_) => "name_taken",
            InvalidName => "invalid_name",
            WrongKind => "wrong_kind",
            InvalidRule(_) => "invalid_rule",
            InvalidSecret(_) => "invalid_secret",
            BackupFailed(_) => "backup_failed",
            BackupMismatch => "backup_mismatch",
            NoBackup => "no_backup",
            BadRequest(_) => "bad_request",
            RuleMismatch(_) => "rule_mismatch",
            HeaderNotAllowed(_) => "header_not_allowed",
            UpstreamFailed(_) => "upstream_failed",
            EncodedReplyRefused => "encoded_reply_refused",
            ReplyTooLarge => "reply_too_large",
            EchoBlocked => "echo_blocked",
            Busy => "busy",
            AuditChainBroken(_) => "audit_chain_broken",
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use VaultError::*;
        match self {
            UnsupportedPlatform => write!(f, "the vault runs only on macOS for now (Linux is planned)"),
            SecureEnclave => write!(f, "the Secure Enclave refused the operation"),
            Keychain => write!(f, "the Keychain refused the operation"),
            KeyProtection => write!(f, "the protected vault key is damaged or can't be opened"),
            Random => write!(f, "the operating system's random number generator failed"),
            AlreadyInitialized => write!(f, "a vault already exists on this Mac"),
            NotInitialized => write!(f, "no vault on this Mac yet; run `vault init`"),
            AutoLoginOn => write!(
                f,
                "macOS automatic login is on; turn it off in System Settings > Users & Groups first \
                 (it keeps the login password in /etc/kcpassword, easy to reverse)"
            ),
            NoSecureEnclave => write!(f, "this Mac has no Secure Enclave"),
            KitNotConfirmed => write!(
                f,
                "the Recovery Kit isn't confirmed yet; run `vault confirm-kit` before storing secrets"
            ),
            KitAlreadyConfirmed => write!(f, "the Recovery Kit is already confirmed"),
            WrongRecoveryKey => write!(f, "that recovery key doesn't match this vault"),
            VaultFileCorrupt => write!(f, "the vault file is damaged or was changed outside the vault"),
            VaultFileUnreadable(why) => write!(f, "can't read the vault file: {why}"),
            UnsafeVaultFolder(why) => write!(f, "the vault folder isn't safe: {why}"),
            Io(why) => write!(f, "file error: {why}"),
            UnknownSecret(name) => write!(f, "no secret named {name:?}"),
            NameTaken(name) => write!(f, "a secret named {name:?} already exists"),
            InvalidName => write!(
                f,
                "names are 1 to 64 characters: letters, digits, dot, dash and underscore"
            ),
            WrongKind => write!(f, "that secret is the wrong kind for this request"),
            InvalidRule(why) => write!(f, "invalid rule: {why}"),
            InvalidSecret(why) => write!(f, "invalid secret: {why}"),
            BackupFailed(why) => write!(f, "backup failed: {why}"),
            BackupMismatch => write!(f, "the backup doesn't match the vault"),
            NoBackup => write!(f, "no backup found"),
            BadRequest(why) => write!(f, "bad request: {why}"),
            RuleMismatch(why) => write!(f, "outside the key's rule: {why}"),
            HeaderNotAllowed(name) => write!(f, "header not allowed: {name}"),
            UpstreamFailed(why) => write!(f, "the request to the API failed: {why}"),
            EncodedReplyRefused => write!(f, "the API sent a compressed reply, which the vault refuses"),
            ReplyTooLarge => write!(f, "the API's reply is too large"),
            EchoBlocked => write!(f, "the API's reply contained the key, so the vault withheld it"),
            Busy => write!(f, "the vault is busy; try again"),
            AuditChainBroken(line) => write!(f, "the audit log's hash chain breaks at line {line}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(error: std::io::Error) -> Self {
        VaultError::Io(error.to_string())
    }
}
