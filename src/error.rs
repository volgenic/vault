//! The vault's errors: a closed list of codes (rule R2). None carries text taken from a secret;
//! the few that carry text carry names, paths or rule fields the caller supplied.

use std::fmt;

use crate::platform::MACHINE;

/// Where to look when the daemon doesn't answer.
#[cfg(target_os = "macos")]
const DAEMON_HINT: &str = "It runs in your login (a LaunchAgent), so after a restart it waits for you to log in; \
     otherwise see ~/Library/Logs/Volgenic/vault.log";
#[cfg(not(target_os = "macos"))]
const DAEMON_HINT: &str = "See `systemctl --user status volgenic-vault` and ~/.local/state/volgenic/vault.log";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    UnsupportedPlatform(String),
    KeyProtection,
    Random,
    AlreadyInitialized,
    NotInitialized,
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
    /// Where the chain breaks: a file and a line.
    AuditChainBroken(String),
    /// The chain doesn't hold the head the vault file recorded: lines were cut off its end.
    AuditHeadMissing,
    AuditUnavailable,
    NotInstalled,
    DaemonNotRunning,
    DaemonNotVerified(String),
    Daemon(String),
    NewerFormat(u32),
    SealedKey(String),
    UnsupportedProtocol(u32),
    ReplyMismatch(String),
    /// A sealed value that doesn't open with the intake key, or isn't what `add_sealed` takes.
    SealedInvalid(String),
    /// The provider refused the credential: the person signs in again.
    CredentialRefused,
    /// The secret is at another version than the request named (the version it has now).
    VersionMismatch(u64),
    /// An import of a login the vault already renews (its name).
    LoginClaimed(String),
    /// The upstream refused an imported login's access token, and the vault may not renew it
    /// until the host's daemon claims it (`claim_refresh`).
    LoginAwaitingClaim,
    /// The upstream sent nothing for the idle timeout.
    IdleTimeout(u64),
    /// `lease` named secrets that may not be leased to a build (their names): not app secrets, or
    /// app secrets not added as leasable.
    NotLeasable(Vec<String>),
    /// `sign` would pass one of the wallet's caps (which, and by how much): nothing was signed.
    OverCap(String),
    /// `fill` named a secret that isn't a login (its name or id as given).
    NoSuchLogin(String),
    /// `fill`'s frame isn't `https:` on the login's registrable domain (why, never a value).
    SiteMismatch(String),
    /// `fill` as Volgenic for Mac from a caller that isn't its signed app (why, never a value).
    NotVolgenicApp(String),
    /// The person at the Mac didn't confirm a sensitive act with Touch ID or their password (why).
    NotConfirmed(String),
}

impl VaultError {
    /// A short stable code for replies on the socket and for the audit log.
    pub fn code(&self) -> &'static str {
        use VaultError::*;
        match self {
            UnsupportedPlatform(_) => "unsupported_platform",
            KeyProtection => "key_protection_error",
            Random => "random_error",
            AlreadyInitialized => "already_initialized",
            NotInitialized => "not_initialized",
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
            AuditChainBroken(_) | AuditHeadMissing => "audit_chain_broken",
            AuditUnavailable => "audit_unavailable",
            NotInstalled => "not_installed",
            DaemonNotRunning => "daemon_not_running",
            DaemonNotVerified(_) => "daemon_not_verified",
            Daemon(_) => "daemon_refused",
            NewerFormat(_) => "newer_format",
            SealedKey(_) => "sealed_key_error",
            UnsupportedProtocol(_) => "unsupported_protocol",
            ReplyMismatch(_) => "reply_mismatch",
            SealedInvalid(_) => "sealed_invalid",
            CredentialRefused => "credential_refused",
            VersionMismatch(_) => "version_mismatch",
            LoginClaimed(_) => "login_claimed",
            LoginAwaitingClaim => "login_awaiting_claim",
            IdleTimeout(_) => "idle_timeout",
            NotLeasable(_) => "not_leasable",
            OverCap(_) => "over_cap",
            NoSuchLogin(_) => "no_such_login",
            SiteMismatch(_) => "site_mismatch",
            NotVolgenicApp(_) => "not_volgenic_app",
            NotConfirmed(_) => "not_confirmed",
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use VaultError::*;
        match self {
            UnsupportedPlatform(what) => write!(f, "{what} isn't available on this platform yet"),
            KeyProtection => write!(f, "the protected vault key is damaged or can't be opened"),
            Random => write!(f, "the operating system's random number generator failed"),
            AlreadyInitialized => write!(f, "a vault already exists on this {MACHINE}"),
            NotInitialized => write!(
                f,
                "no vault on this {MACHINE}: install one with `vault install`, or restore one with `vault restore`"
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
            AuditChainBroken(place) => write!(f, "the audit log's hash chain breaks at {place}"),
            AuditHeadMissing => write!(
                f,
                "the audit log's hash chain doesn't reach the head the vault file recorded: lines were cut off its end"
            ),
            AuditUnavailable => write!(
                f,
                "the vault can't write its audit log, so it refuses every use until it can (R28)"
            ),
            NotInstalled => write!(f, "the vault isn't installed for you on this {MACHINE}; run `vault install`"),
            DaemonNotRunning => write!(f, "the vault's daemon isn't answering. {DAEMON_HINT}"),
            DaemonNotVerified(why) => write!(f, "refusing to talk to the socket: {why}"),
            Daemon(message) => write!(f, "{message}"),
            NewerFormat(format) => write!(
                f,
                "the vault file is format {format}, written by a newer build of the vault; install that build"
            ),
            SealedKey(why) => write!(f, "the sealed vault key can't be opened: {why}"),
            UnsupportedProtocol(version) => write!(
                f,
                "protocol {version} is newer than this vault speaks (protocol {})",
                crate::protocol::PROTOCOL_VERSION
            ),
            ReplyMismatch(why) => write!(f, "the daemon's reply doesn't belong to this request: {why}"),
            SealedInvalid(why) => write!(f, "sealed value refused: {why}"),
            CredentialRefused => write!(f, "the provider refused the credential; sign in again"),
            VersionMismatch(have) => write!(
                f,
                "the secret is at version {have} now, not the one named: it changed meanwhile (import it again, then claim that version)"
            ),
            LoginAwaitingClaim => write!(
                f,
                "the provider refused the login's access token, and the vault may not renew it until the host's daemon claims it (claim_refresh)"
            ),
            LoginClaimed(name) => write!(
                f,
                "the vault already renews {name:?}, so a file's tokens are older than the vault's and may be dead; only a new sign-in (add_sealed with replace) replaces it"
            ),
            IdleTimeout(seconds) => write!(f, "the API sent nothing for {seconds} seconds"),
            NotLeasable(names) => write!(
                f,
                "not leased: {} may not be leased to builds (only an app_secret added as leasable may be); nothing was sealed",
                names.iter().map(|name| format!("{name:?}")).collect::<Vec<_>>().join(", ")
            ),
            OverCap(why) => write!(f, "not signed: {why}; only the person at the vault's {MACHINE} can raise a wallet's caps"),
            NoSuchLogin(name) => write!(f, "no saved login {name:?}"),
            SiteMismatch(why) => write!(f, "not the login's site, so nothing was filled: {why}"),
            NotVolgenicApp(why) => write!(f, "only Volgenic for Mac's signed app fills as the app, so nothing was filled: {why}"),
            NotConfirmed(why) => write!(f, "not confirmed by the person at this {MACHINE}, so nothing was done: {why}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(error: std::io::Error) -> Self {
        VaultError::Io(error.to_string())
    }
}
