//! The vault's operations, shared by the command-line tool and `serve`. Nothing here returns a
//! secret value: results are summaries, codes, statuses and reports (R4).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::audit::{self, AuditEvent};
use crate::backup;
use crate::client;
use crate::error::VaultError;
use crate::keyprotect;
use crate::model::{self, BackupStatus, Kind, Record, SecretSummary, VAULT_FORMAT, VaultDoc};
use crate::platform;
use crate::rules::ProxyRule;
use crate::secret::SecretValue;
use crate::store::{self, Paths};
use crate::totp::{self, TotpCode};

/// An open vault: its paths, its key and its decrypted document.
pub struct Vault {
    pub(crate) paths: Paths,
    pub(crate) key: SecretValue,
    pub(crate) doc: VaultDoc,
}

/// A new secret as the person typed it into `vault add`.
pub struct NewSecret {
    pub name: String,
    pub kind: Kind,
    pub site: String,
    pub rule: Option<ProxyRule>,
    pub username: Option<String>,
    /// For a 2FA seed: the base32 seed or the otpauth link.
    pub value: SecretValue,
}

pub struct InitOptions {
    pub kit_path: PathBuf,
    pub backup_dir: PathBuf,
}

pub struct InitReport {
    pub vault_id: String,
    pub recovery_fingerprint: String,
    pub kit_path: PathBuf,
    pub backup_dir: PathBuf,
}

pub struct VerifyReport {
    pub file: PathBuf,
    pub generation: u64,
    pub written_at: String,
    pub secrets: usize,
    pub matches_vault: bool,
    pub newest: bool,
    pub recovery_key_opens: Option<bool>,
    /// The backup as it was checked: age ciphertext, safe to keep (R21).
    pub ciphertext: Vec<u8>,
}

pub struct RestoreReport {
    pub vault_id: String,
    pub from_vault_id: String,
    pub secrets: Vec<SecretSummary>,
    pub from_generation: u64,
}

/// What `vault status` shows. Information only; no values.
pub struct StatusReport {
    pub vault_folder: PathBuf,
    pub vault_exists: bool,
    pub key_file: bool,
    pub secure_enclave: bool,
    pub key_protection: &'static str,
    pub auto_login_on: bool,
    pub filevault: String,
    pub signature: String,
    pub serve_running: bool,
    pub opened: Option<OpenedStatus>,
    pub open_error: Option<VaultError>,
}

pub struct OpenedStatus {
    pub vault_id: String,
    pub created_at: String,
    pub recovery_fingerprint: String,
    pub kit_confirmed: bool,
    pub backup_dir: String,
    pub generation: u64,
    pub secrets: usize,
    pub by_kind: Vec<(Kind, usize)>,
    pub last_backup: Option<BackupStatus>,
    pub audit_chain: Result<usize, VaultError>,
    pub recent_changes: Vec<String>,
}

fn check_auto_login() -> Result<(), VaultError> {
    if platform::auto_login_on() { Err(VaultError::AutoLoginOn) } else { Ok(()) }
}

/// Appends to the audit log if the vault folder exists. The log is best-effort here only for
/// read-only commands run before any vault exists.
fn audit_event(paths: &Paths, event: AuditEvent) -> Result<String, VaultError> {
    audit::append(&paths.audit_log, event)
}

/// Sets up a new vault (R17, R31). Refuses if any trace of a vault exists.
pub fn init(paths: &Paths, options: &InitOptions) -> Result<InitReport, VaultError> {
    check_auto_login()?;
    if !keyprotect::hardware_available() {
        return Err(VaultError::NoSecureEnclave);
    }
    store::ensure_private_dir(&paths.dir)?;
    let _lock = store::lock_for_change(paths)?;
    if store::vault_exists(paths) || keyprotect::exists(&paths.dir) {
        return Err(VaultError::AlreadyInitialized);
    }

    let (recovery_secret, recovery_public) = backup::new_identity();
    let (check_secret, _check_public) = backup::new_identity();
    let vault_id = store::new_vault_id()?;
    let fingerprint = backup::fingerprint(&recovery_public);
    let created_at = crate::now_rfc3339();

    write_kit(&options.kit_path, &recovery_secret, &recovery_public, &fingerprint, &created_at)?;
    drop(recovery_secret);

    let key = SecretValue::random(32)?;
    if let Err(error) = keyprotect::store_new(&paths.dir, &key) {
        let _ = wipe_file(&options.kit_path);
        return Err(error);
    }

    let mut doc = VaultDoc {
        format: VAULT_FORMAT,
        vault_id: vault_id.clone(),
        created_at,
        recovery_recipient: recovery_public,
        kit_confirmed: false,
        kit_path: Some(options.kit_path.display().to_string()),
        backup_dir: options.backup_dir.display().to_string(),
        check_identity: check_secret,
        audit_head: audit::GENESIS.into(),
        generation: 1,
        last_backup: None,
        records: Vec::new(),
    };
    let mut event = AuditEvent::new("init", "ok");
    event.detail = Some(format!("vault {vault_id}, recovery key {fingerprint}"));
    doc.audit_head = audit_event(paths, event)?;
    store::save(paths, &key, &doc)?;
    // The first backup comes next, from `serve` (R32): the command-line tool starts it, then
    // calls `Vault::backup`.
    Ok(InitReport {
        vault_id,
        recovery_fingerprint: fingerprint,
        kit_path: options.kit_path.clone(),
        backup_dir: options.backup_dir.clone(),
    })
}

/// Writes the Recovery Kit: the one place the recovery private key is ever written, a file
/// readable only by the user, never the terminal (R17). The kit call site of `expose` in R1.
fn write_kit(
    path: &Path,
    recovery_secret: &SecretValue,
    recovery_public: &str,
    fingerprint: &str,
    created_at: &str,
) -> Result<(), VaultError> {
    let secret = std::str::from_utf8(recovery_secret.expose()).map_err(|_| VaultError::Random)?;
    let text = zeroize::Zeroizing::new(format!(
        "VOLGENIC VAULT RECOVERY KIT\n\
         ===========================\n\
         \n\
         Made: {created_at}\n\
         Recovery key fingerprint: {fingerprint}\n\
         \n\
         Your recovery key (keep it secret; it opens every backup of your vault):\n\
         \n\
         {secret}\n\
         \n\
         Its public half, for reference: {recovery_public}\n\
         \n\
         What to do now:\n\
         1. Print this page, or save the key in your password manager, or both.\n\
         2. Run `vault confirm-kit` and paste the key back when asked. The vault checks it,\n\
            then deletes this file. It stores no secret until you do.\n\
         \n\
         If your Mac is lost or its Secure Enclave dies, this key plus a backup file brings\n\
         the vault back: `vault restore <backup file>`. Backups are standard age files, so\n\
         `age -d -i <file holding this key> <backup>` also opens them without Volgenic.\n\
         Nobody else, Volgenic included, can open your backups. Lose this key and a dead\n\
         Mac means the secrets are gone.\n"
    ));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| VaultError::Io(format!("can't create the kit at {}: {e}", path.display())))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Overwrites a file with zeros, then deletes it. Best effort: an SSD may keep old blocks.
fn wipe_file(path: &Path) -> Result<(), VaultError> {
    if let Ok(meta) = fs::metadata(path) {
        if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
            let _ = file.write_all(&vec![0u8; meta.len() as usize]);
            let _ = file.sync_all();
        }
        fs::remove_file(path)?;
    }
    Ok(())
}

impl Vault {
    /// Opens the vault on this Mac: unwraps the vault key, then decrypts the vault file.
    pub fn open(paths: &Paths) -> Result<Vault, VaultError> {
        if !store::vault_exists(paths) {
            return Err(VaultError::NotInitialized);
        }
        store::check_private_dir(&paths.dir)?;
        let key = keyprotect::load(&paths.dir)?;
        let doc = store::load(paths, &key)?;
        Ok(Vault { paths: paths.clone(), key, doc })
    }

    pub fn summaries(&self) -> Vec<SecretSummary> {
        self.doc.summaries()
    }

    pub fn vault_id(&self) -> &str {
        &self.doc.vault_id
    }

    pub fn kit_confirmed(&self) -> bool {
        self.doc.kit_confirmed
    }

    /// Re-reads the vault file under the change lock, so a change always starts from what is on
    /// disk now, never from the copy read before a prompt (another change may have landed).
    fn reload(&mut self) -> Result<(), VaultError> {
        self.doc = store::load(&self.paths, &self.key)?;
        Ok(())
    }

    /// A vault that never held a secret: its kit isn't confirmed, so nothing could be stored.
    pub fn is_unused(&self) -> bool {
        !self.doc.kit_confirmed && self.doc.records.is_empty()
    }

    pub fn audit(&self, event: AuditEvent) -> Result<String, VaultError> {
        audit_event(&self.paths, event)
    }

    /// Records a change: audit line first (so the head covers it), then the vault file, then a
    /// backup that is read back and checked (R18, R19, R29).
    fn commit(&mut self, event: AuditEvent) -> Result<BackupStatus, VaultError> {
        self.doc.generation += 1;
        self.doc.audit_head = audit_event(&self.paths, event)?;
        store::save(&self.paths, &self.key, &self.doc)?;
        let status = self.backup_now();
        if status.ok { Ok(status) } else { Err(VaultError::BackupFailed(status.detail)) }
    }

    /// Asks `serve` for the current generation's backup and records the result. Used by
    /// `vault init` and `vault restore` once `serve` runs, and by `vault backup` to retry.
    pub fn backup(&mut self) -> Result<BackupStatus, VaultError> {
        let _lock = store::lock_for_change(&self.paths)?;
        self.reload()?;
        Ok(self.backup_now())
    }

    /// Has `serve` write and verify a backup (R32), records the result in the vault file and
    /// the audit log, and returns it. A failure is the alarm of R19: audit entry, `status`,
    /// the log.
    fn backup_now(&mut self) -> BackupStatus {
        let status = match client::request_backup(&self.paths) {
            Ok(status) => status,
            Err(error) => BackupStatus {
                file: String::new(),
                at: crate::now_rfc3339(),
                generation: self.doc.generation,
                ok: false,
                detail: error.to_string(),
            },
        };
        let mut event = AuditEvent::new("backup", if status.ok { "ok" } else { "FAILED" });
        event.detail = Some(if status.ok {
            format!("generation {} {}: {}", status.generation, status.detail, status.file)
        } else {
            format!("ALARM: {}", status.detail)
        });
        let _ = audit_event(&self.paths, event);
        if !status.ok {
            eprintln!("vault: BACKUP FAILED: {}", status.detail);
        }
        self.doc.last_backup = Some(status.clone());
        let _ = store::save(&self.paths, &self.key, &self.doc);
        status
    }

    /// Before any change: the kit must be confirmed (R17) and the last backup good (R19).
    fn ready_for_change(&mut self) -> Result<(), VaultError> {
        if !self.doc.kit_confirmed {
            return Err(VaultError::KitNotConfirmed);
        }
        if !self.doc.last_backup.as_ref().is_some_and(|b| b.ok) {
            let status = self.backup_now();
            if !status.ok {
                return Err(VaultError::BackupFailed(format!(
                    "the last backup failed and a retry failed too ({}); no changes until a backup succeeds",
                    status.detail
                )));
            }
        }
        Ok(())
    }

    /// Confirms the Recovery Kit with the recovery key the person typed back (R17).
    pub fn confirm_kit(&mut self, typed: SecretValue) -> Result<BackupStatus, VaultError> {
        let _lock = store::lock_for_change(&self.paths)?;
        self.reload()?;
        if self.doc.kit_confirmed {
            return Err(VaultError::KitAlreadyConfirmed);
        }
        let identity = backup::parse_identity(&typed);
        drop(typed);
        let matches = identity.as_ref().is_ok_and(|id| backup::public_of(id) == self.doc.recovery_recipient);
        if !matches {
            let _ = self.audit(AuditEvent::new("confirm-kit", "denied: wrong recovery key"));
            return Err(VaultError::WrongRecoveryKey);
        }
        let mut kit_note = "kit file already gone".to_string();
        if let Some(kit) = self.doc.kit_path.take() {
            let kit = PathBuf::from(kit);
            if kit.exists() {
                kit_note = match wipe_file(&kit) {
                    Ok(()) => format!("kit file {} deleted", kit.display()),
                    Err(e) => format!("couldn't delete kit file {}: {e}", kit.display()),
                };
            }
        }
        self.doc.kit_confirmed = true;
        let mut event = AuditEvent::new("confirm-kit", "ok");
        event.detail = Some(kit_note);
        self.commit(event)
    }

    /// Stores a new secret (R5, R7, R17, R27).
    pub fn add(&mut self, new: NewSecret) -> Result<(SecretSummary, BackupStatus), VaultError> {
        let _lock = store::lock_for_change(&self.paths)?;
        self.reload()?;
        self.ready_for_change()?;
        model::validate_name(&new.name)?;
        model::validate_site(&new.site)?;
        if self.doc.find(&new.name).is_some() {
            return Err(VaultError::NameTaken(new.name));
        }
        if new.value.is_empty() || new.value.len() > 16 * 1024 {
            return Err(VaultError::InvalidSecret("the value must be 1 byte to 16 KiB".into()));
        }
        let (value, totp_params) = match new.kind {
            Kind::TwoFactor => {
                let (seed, params) = totp::parse_seed_input(&new.value)?;
                (seed, Some(params))
            }
            _ => (new.value, None),
        };
        match new.kind {
            Kind::ApiKey if new.rule.is_none() => {
                return Err(VaultError::InvalidRule("an API key needs a rule".into()));
            }
            Kind::Login if new.username.as_deref().is_none_or(str::is_empty) => {
                return Err(VaultError::InvalidSecret("a login needs a username".into()));
            }
            _ => {}
        }
        let record = Record {
            name: new.name.clone(),
            kind: new.kind,
            site: new.site,
            created_at: crate::now_rfc3339(),
            rule: if new.kind == Kind::ApiKey { new.rule } else { None },
            username: if new.kind == Kind::Login { new.username } else { None },
            totp: totp_params,
            value,
        };
        let summary = record.summary();
        let mut event = AuditEvent::named("add", &record.name, "ok");
        event.detail = Some(match &record.rule {
            Some(rule) => format!("{}; rule {}", record.kind.label(), rule.describe()),
            None => format!("{} for {}", record.kind.label(), record.site),
        });
        self.doc.records.push(record);
        let status = self.commit(event)?;
        Ok((summary, status))
    }

    /// Deletes a secret. Earlier backup generations still hold it (R18).
    pub fn delete(&mut self, name: &str) -> Result<BackupStatus, VaultError> {
        let _lock = store::lock_for_change(&self.paths)?;
        self.reload()?;
        self.ready_for_change()?;
        let before = self.doc.records.len();
        self.doc.records.retain(|record| record.name != name);
        if self.doc.records.len() == before {
            return Err(VaultError::UnknownSecret(name.into()));
        }
        self.commit(AuditEvent::named("delete", name, "ok"))
    }

    /// The current 2FA code for a stored seed, from the vault's own clock (R5, R6).
    pub fn totp_code(&self, name: &str) -> Result<TotpCode, VaultError> {
        totp_code(&self.doc, name)
    }

    /// Checks a backup (the newest by default) against the vault: decrypts it with the check
    /// key and compares every secret; with the recovery key, also proves the kit opens it.
    pub fn verify_backup(&self, file: Option<PathBuf>, recovery: Option<SecretValue>) -> Result<VerifyReport, VaultError> {
        // The newest backup comes from `serve`, the only program that touches the backup
        // folder (R32); a file the person names is read directly.
        let newest = file.is_none();
        let (file, data) = match file {
            Some(file) => {
                let data = fs::read(&file)
                    .map_err(|e| VaultError::BackupFailed(format!("can't read {}: {e}", file.display())))?;
                (file, data)
            }
            None => {
                let (file, data) = client::request_newest_backup(&self.paths)?;
                (PathBuf::from(file), data)
            }
        };
        let check = backup::parse_identity(&self.doc.check_identity)?;
        let payload = backup::open_bytes(&data, &check)?;
        let matches_vault = payload.vault_id == self.doc.vault_id
            && payload.recovery_recipient == self.doc.recovery_recipient
            && same_records(&payload.records, &self.doc.records);
        let recovery_key_opens = match recovery {
            None => None,
            Some(typed) => {
                let identity = backup::parse_identity(&typed);
                drop(typed);
                Some(match identity {
                    Ok(identity) => backup::public_of(&identity) == self.doc.recovery_recipient
                        && backup::open_bytes(&data, &identity).is_ok(),
                    Err(_) => false,
                })
            }
        };
        let mut event = AuditEvent::new("verify-backup", if matches_vault { "ok" } else { "differs from vault" });
        event.detail = Some(format!(
            "{} (generation {}){}",
            file.display(),
            payload.generation,
            match recovery_key_opens {
                Some(true) => ", recovery key opens it",
                Some(false) => ", RECOVERY KEY DOES NOT OPEN IT",
                None => "",
            }
        ));
        let _ = self.audit(event);
        Ok(VerifyReport {
            newest,
            file,
            generation: payload.generation,
            written_at: payload.written_at,
            secrets: payload.records.len(),
            matches_vault,
            recovery_key_opens,
            ciphertext: data,
        })
    }
}

pub(crate) fn totp_code(doc: &VaultDoc, name: &str) -> Result<TotpCode, VaultError> {
    let record = doc.find(name).ok_or_else(|| VaultError::UnknownSecret(name.into()))?;
    if record.kind != Kind::TwoFactor {
        return Err(VaultError::WrongKind);
    }
    totp::code_at(&record.value, record.totp.unwrap_or_default(), crate::now_unix())
}

/// Whether two record lists hold the same secrets: names, kinds, sites, rules and values.
pub(crate) fn same_records(a: &[Record], b: &[Record]) -> bool {
    a.len() == b.len()
        && a.iter().all(|x| {
            b.iter().any(|y| {
                x.name == y.name
                    && x.kind == y.kind
                    && x.site == y.site
                    && x.rule == y.rule
                    && x.username == y.username
                    && x.totp == y.totp
                    && x.value.same_as(&y.value)
            })
        })
}

/// Where `vault reset` leaves a copy of the newest backup, in the vault folder, so `vault restore`
/// can run without opening the backup folder from the terminal (R32).
const RESTORE_POINT: &str = "restore-point.age";
const RESTORE_POINT_INFO: &str = "restore-point.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct RestorePointInfo {
    backup_dir: String,
    file: String,
}

/// Whether `vault reset` left a restore point on this Mac.
pub fn has_restore_point(paths: &Paths) -> bool {
    paths.dir.join(RESTORE_POINT).is_file()
}

/// Restores a backup into a fresh vault on this Mac, with the recovery key (R20). The backup is
/// the file the person names, or the restore point `vault reset` left. Makes a new Secure
/// Enclave key, a new vault key and a new vault id: the restored vault starts its own line of
/// backups, so it never collides with the generations still in the folder, which stay as they
/// are.
pub fn restore(paths: &Paths, file: Option<&Path>, typed: SecretValue) -> Result<RestoreReport, VaultError> {
    check_auto_login()?;
    if !keyprotect::hardware_available() {
        return Err(VaultError::NoSecureEnclave);
    }
    store::ensure_private_dir(&paths.dir)?;
    let _lock = store::lock_for_change(paths)?;
    if store::vault_exists(paths) || keyprotect::exists(&paths.dir) {
        return Err(VaultError::AlreadyInitialized);
    }
    let (source, data, backup_dir) = match file {
        Some(file) => {
            let data = fs::read(file)
                .map_err(|e| VaultError::BackupFailed(format!("can't read {}: {e}", file.display())))?;
            let dir = file.parent().map(Path::to_path_buf).unwrap_or_else(|| paths.local_backups.clone());
            (file.display().to_string(), data, dir)
        }
        None => {
            let info: RestorePointInfo = fs::read(paths.dir.join(RESTORE_POINT_INFO))
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .ok_or(VaultError::NoBackup)?;
            let data = fs::read(paths.dir.join(RESTORE_POINT)).map_err(|_| VaultError::NoBackup)?;
            (info.file, data, PathBuf::from(info.backup_dir))
        }
    };
    let identity = backup::parse_identity(&typed)?;
    drop(typed);
    let payload = backup::open_bytes(&data, &identity)?;
    if payload.recovery_recipient != backup::public_of(&identity) {
        return Err(VaultError::WrongRecoveryKey);
    }
    let (check_secret, _) = backup::new_identity();
    let vault_id = store::new_vault_id()?;
    let key = SecretValue::random(32)?;
    keyprotect::store_new(&paths.dir, &key)?;

    let secrets = payload.records.iter().map(Record::summary).collect();
    let mut doc = VaultDoc {
        format: VAULT_FORMAT,
        vault_id: vault_id.clone(),
        created_at: crate::now_rfc3339(),
        recovery_recipient: payload.recovery_recipient,
        kit_confirmed: true,
        kit_path: None,
        backup_dir: backup_dir.display().to_string(),
        check_identity: check_secret,
        audit_head: audit::GENESIS.into(),
        generation: 1,
        last_backup: None,
        records: payload.records,
    };
    let mut event = AuditEvent::new("restore", "ok");
    event.detail = Some(format!(
        "new vault {vault_id} from {source} (vault {}, generation {}), audit head then {}",
        payload.vault_id, payload.generation, payload.audit_head
    ));
    doc.audit_head = audit_event(paths, event)?;
    store::save(paths, &key, &doc)?;
    if file.is_none() {
        let _ = fs::remove_file(paths.dir.join(RESTORE_POINT));
        let _ = fs::remove_file(paths.dir.join(RESTORE_POINT_INFO));
    }
    Ok(RestoreReport {
        vault_id,
        from_vault_id: payload.vault_id,
        secrets,
        from_generation: payload.generation,
    })
}

/// Removes this Mac's vault so a backup can be restored into a fresh one (R20). Needs the
/// recovery key, and only goes ahead when the newest backup opens with it and matches the
/// vault, so nothing is lost. Keeps the backups and the audit log.
pub fn reset(paths: &Paths, typed: SecretValue) -> Result<PathBuf, VaultError> {
    let _lock = store::lock_for_change(paths)?;
    let vault = Vault::open(paths)?;
    if vault.is_unused() {
        drop(typed);
        return remove_unused(paths, &vault);
    }
    let identity = backup::parse_identity(&typed);
    let report = vault.verify_backup(None, Some(typed))?;
    let proven = identity.is_ok_and(|id| backup::public_of(&id) == vault.doc.recovery_recipient)
        && report.recovery_key_opens == Some(true);
    if !proven {
        let _ = vault.audit(AuditEvent::new("reset", "denied: wrong recovery key"));
        return Err(VaultError::WrongRecoveryKey);
    }
    if !report.matches_vault {
        let _ = vault.audit(AuditEvent::new("reset", "denied: newest backup differs from vault"));
        return Err(VaultError::BackupMismatch);
    }
    // A copy of the backup just proven, in the vault folder, so `vault restore` needs no
    // access to the backup folder (R32). Ciphertext only.
    store::write_atomic(&paths.dir.join(RESTORE_POINT), &report.ciphertext)?;
    let info = RestorePointInfo { backup_dir: vault.doc.backup_dir.clone(), file: report.file.display().to_string() };
    let info = serde_json::to_vec(&info).map_err(|_| VaultError::Io("restore point encoding".into()))?;
    store::write_atomic(&paths.dir.join(RESTORE_POINT_INFO), &info)?;
    let mut event = AuditEvent::new("reset", "ok");
    event.detail = Some(format!(
        "vault removed (vault file and key.se); newest backup {} kept as {RESTORE_POINT}",
        report.file.display()
    ));
    vault.audit(event)?;
    keyprotect::remove(&paths.dir)?;
    fs::remove_file(&paths.vault_file)?;
    Ok(report.file)
}

/// Removes a vault that never held a secret: the kit isn't confirmed, so nothing could be
/// stored (R17). This is how setup starts over, for example when the first backup to the
/// chosen folder failed. Anyone who could do this could already read the unconfirmed kit.
pub fn reset_unused(paths: &Paths) -> Result<(), VaultError> {
    let _lock = store::lock_for_change(paths)?;
    let vault = Vault::open(paths)?;
    if !vault.is_unused() {
        return Err(VaultError::KitAlreadyConfirmed);
    }
    remove_unused(paths, &vault).map(|_| ())
}

fn remove_unused(paths: &Paths, vault: &Vault) -> Result<PathBuf, VaultError> {
    let mut event = AuditEvent::new("reset", "ok");
    event.detail = Some("unused vault removed (kit not confirmed, no secrets); vault file and key.se".into());
    vault.audit(event)?;
    if let Some(kit) = &vault.doc.kit_path {
        let _ = wipe_file(Path::new(kit));
    }
    keyprotect::remove(&paths.dir)?;
    fs::remove_file(&paths.vault_file)?;
    Ok(PathBuf::new())
}

/// Gathers `vault status`. Opens the vault only if it exists.
pub fn status(paths: &Paths) -> StatusReport {
    let vault_exists = store::vault_exists(paths);
    let serve_running = std::os::unix::net::UnixStream::connect(&paths.socket).is_ok();
    let mut report = StatusReport {
        vault_folder: paths.dir.clone(),
        vault_exists,
        key_file: keyprotect::exists(&paths.dir),
        secure_enclave: keyprotect::hardware_available(),
        key_protection: keyprotect::DESCRIPTION,
        auto_login_on: platform::auto_login_on(),
        filevault: platform::filevault_status(),
        signature: platform::own_signature(),
        serve_running,
        opened: None,
        open_error: None,
    };
    if !vault_exists {
        return report;
    }
    match Vault::open(paths) {
        Err(error) => report.open_error = Some(error),
        Ok(vault) => {
            let doc = &vault.doc;
            let mut by_kind = Vec::new();
            for kind in [Kind::ApiKey, Kind::Login, Kind::TwoFactor] {
                by_kind.push((kind, doc.records.iter().filter(|r| r.kind == kind).count()));
            }
            let audit_chain = audit::read_and_verify(&paths.audit_log).and_then(|(lines, _)| {
                if audit::chain_contains(&paths.audit_log, &doc.audit_head)? {
                    Ok(lines.len())
                } else {
                    Err(VaultError::AuditChainBroken(0))
                }
            });
            let recent_changes = audit::read_and_verify(&paths.audit_log)
                .map(|(lines, _)| {
                    lines
                        .iter()
                        .rev()
                        .filter(|l| matches!(l.event.event.as_str(), "add" | "delete" | "restore" | "confirm-kit" | "init"))
                        .take(5)
                        .map(|l| format!("{}  {} {}", l.t, l.event.event, l.event.name.clone().unwrap_or_default()))
                        .collect()
                })
                .unwrap_or_default();
            report.opened = Some(OpenedStatus {
                vault_id: doc.vault_id.clone(),
                created_at: doc.created_at.clone(),
                recovery_fingerprint: backup::fingerprint(&doc.recovery_recipient),
                kit_confirmed: doc.kit_confirmed,
                backup_dir: doc.backup_dir.clone(),
                generation: doc.generation,
                secrets: doc.records.len(),
                by_kind,
                last_backup: doc.last_backup.clone(),
                audit_chain,
                recent_changes,
            });
            let _ = vault.audit(AuditEvent::new("status", "ok"));
        }
    }
    report
}
