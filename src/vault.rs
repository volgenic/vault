//! The vault's operations. They run only in the daemon, a LaunchAgent in the owner's login, and
//! in `vault install` for the first vault (R13). The command-line tool
//! never opens the vault; it asks the daemon. Nothing here returns a secret value: results are
//! summaries, codes, statuses and reports (R4).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::audit::{self, AuditEvent};
use crate::backup;
use crate::error::VaultError;
use crate::keyprotect;
use crate::model::{self, BackupStatus, Kind, Record, SecretSummary, VAULT_FORMAT, VaultDoc};
use crate::protocol::{AuditReply, BackupCheck, OpenedStatus};
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

pub struct InitReport {
    pub vault_id: String,
    pub recovery_fingerprint: String,
    pub kit_path: PathBuf,
    pub mirror_dir: PathBuf,
}

pub struct RestoreReport {
    pub vault_id: String,
    pub from_vault_id: String,
    pub secrets: Vec<SecretSummary>,
    pub from_generation: u64,
}

/// What `reset` did: removed an unused vault, or proved the key and kept a restore point.
pub struct ResetOutcome {
    pub unused: bool,
    pub newest_file: Option<String>,
    /// The kit file, for the command-line tool to delete (it is the owner's file).
    pub kit_path: Option<String>,
}

fn audit_event(paths: &Paths, event: AuditEvent) -> Result<String, VaultError> {
    audit::append(&paths.audit_log, event)
}

/// Makes a new vault (R16, R17). Runs in `vault install`, before the daemon starts. The first
/// backup comes from the daemon when it starts. No gate: secrets can be stored right away; the
/// kit stays in the owner's home folder until he stashes it.
pub fn init(paths: &Paths, kit_path: &Path, mirror_dir: &Path) -> Result<InitReport, VaultError> {
    if store::vault_exists(paths) || keyprotect::key_exists(&paths.dir) {
        return Err(VaultError::AlreadyInitialized);
    }

    let (recovery_secret, recovery_public) = backup::new_identity();
    let (check_secret, _check_public) = backup::new_identity();
    let vault_id = store::new_vault_id()?;
    let fingerprint = backup::fingerprint(&recovery_public);
    let created_at = crate::now_rfc3339();

    write_kit(kit_path, &recovery_secret, &recovery_public, &fingerprint, &created_at)?;
    drop(recovery_secret);

    let key = SecretValue::random(32)?;
    if let Err(error) = keyprotect::store_new(&paths.dir, &key) {
        let _ = wipe_file(kit_path);
        return Err(error);
    }

    let mut doc = VaultDoc {
        format: VAULT_FORMAT,
        vault_id: vault_id.clone(),
        created_at,
        recovery_recipient: recovery_public,
        kit_confirmed: false,
        kit_path: Some(kit_path.display().to_string()),
        mirror_dir: mirror_dir.display().to_string(),
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
    Ok(InitReport {
        vault_id,
        recovery_fingerprint: fingerprint,
        kit_path: kit_path.to_path_buf(),
        mirror_dir: mirror_dir.to_path_buf(),
    })
}

/// Writes the Recovery Kit: the one place the recovery private key is ever written, a file
/// readable only by its owner, never the terminal (R17). The kit call site of `expose` in R1.
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
         2. Optionally run `vault confirm-kit` and paste the key back; the vault checks it\n\
            and deletes this file. The vault works either way.\n\
         \n\
         If your Mac is lost, this key plus a backup file brings the vault back on another\n\
         Mac: `vault install --for-restore`, then\n\
         `vault restore <backup file>`. Backups are standard age files, so\n\
         `age -d -i <file holding this key> <backup>` also opens them without Volgenic.\n\
         Nobody else, Volgenic included, can open your backups. Lose this key and a dead\n\
         Mac means the secrets are gone.\n"
    ));
    // `create_new` refuses an existing file or symbolic link at the path, and the caller runs
    // this as the kit's owner, so the write can't land anywhere that user can't write.
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
pub fn wipe_file(path: &Path) -> Result<(), VaultError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(_) => return Ok(()),
    };
    if meta.is_file() {
        if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
            let _ = file.write_all(&vec![0u8; meta.len() as usize]);
            let _ = file.sync_all();
        }
    }
    fs::remove_file(path)?;
    Ok(())
}

impl Vault {
    /// Opens the vault: reads the vault key file, then decrypts the vault file.
    pub fn open(paths: &Paths) -> Result<Vault, VaultError> {
        if !store::vault_exists(paths) {
            return Err(VaultError::NotInitialized);
        }
        let key = keyprotect::load(&paths.dir)?;
        let doc = store::load(paths, &key)?;
        Ok(Vault { paths: paths.clone(), key, doc })
    }

    /// A fresh copy of the vault as it is on disk, for the daemon's read-only snapshot.
    pub(crate) fn read_copy(&self) -> Result<VaultDoc, VaultError> {
        store::load(&self.paths, &self.key)
    }

    pub fn vault_id(&self) -> &str {
        &self.doc.vault_id
    }

    /// Starts every change from the vault as it is on disk, so a change that failed halfway
    /// never leaks into the next one (R13).
    fn reload(&mut self) -> Result<(), VaultError> {
        self.doc = store::load(&self.paths, &self.key)?;
        Ok(())
    }

    /// A vault that never held a secret: no change since `vault install` made it (every add,
    /// delete or kit confirmation raises the generation), and not restored from a backup (a
    /// restored vault counts as confirmed). Only such a vault may be removed without the
    /// recovery key, together with its kit; any other keeps its kit and needs the key, because
    /// its backups may hold secrets only the kit opens.
    pub fn is_unused(&self) -> bool {
        self.doc.generation == 1 && !self.doc.kit_confirmed && self.doc.records.is_empty()
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

    /// Writes (if not written yet) and checks the current generation's backup. Used at the
    /// daemon's start and by `vault backup` to retry.
    pub fn backup(&mut self) -> Result<BackupStatus, VaultError> {
        self.reload()?;
        Ok(self.backup_now())
    }

    /// Whether the current generation still needs its backup.
    pub fn needs_backup(&self) -> bool {
        !self.doc.last_backup.as_ref().is_some_and(|b| b.ok && b.generation == self.doc.generation)
    }

    /// Writes and verifies a backup in the local backup folder, records the result in the vault
    /// file and the audit log, and returns it. A failure is the alarm of R19: audit entry,
    /// `status`, the log.
    fn backup_now(&mut self) -> BackupStatus {
        let status = match backup::write_and_verify(&self.doc, &self.paths.local_backups) {
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

    /// Before any change: the last backup must be good (R19).
    fn ready_for_change(&mut self) -> Result<(), VaultError> {
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

    /// Confirms the Recovery Kit with the recovery key the person typed back (R17). Returns the
    /// kit file's path for the command-line tool to delete.
    pub fn confirm_kit(&mut self, typed: SecretValue) -> Result<(BackupStatus, Option<String>), VaultError> {
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
        let kit_path = self.doc.kit_path.take();
        self.doc.kit_confirmed = true;
        let mut event = AuditEvent::new("confirm-kit", "ok");
        event.detail = kit_path.as_ref().map(|kit| format!("kit file {kit} handed to the command-line tool to delete"));
        let status = self.commit(event)?;
        Ok((status, kit_path))
    }

    /// Stores a new secret (R5, R7, R17, R27).
    pub fn add(&mut self, new: NewSecret) -> Result<(SecretSummary, BackupStatus), VaultError> {
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
            Kind::Login => model::validate_username(new.username.as_deref().unwrap_or(""))?,
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
        // Every backup must stay small enough for `vault restore FILE` to take back. Measured
        // exactly, with the new record in place; 4 KiB covers what the next commit changes (the
        // audit head, the generation, the timestamp).
        self.doc.records.push(record);
        let measured = backup::plaintext_size(&self.doc, &self.doc.records);
        if measured.as_ref().map_or(true, |size| size.saturating_add(4096) > backup::MAX_VAULT_PLAINTEXT) {
            drop(self.doc.records.pop());
            return Err(match measured {
                Err(e) => e,
                Ok(_) => VaultError::InvalidSecret(format!(
                    "the vault is full: its backup would pass {} MiB, the most a restore takes",
                    backup::MAX_VAULT_PLAINTEXT / (1024 * 1024)
                )),
            });
        }
        let status = self.commit(event)?;
        Ok((summary, status))
    }

    /// Deletes a secret. Earlier backup generations still hold it (R18).
    pub fn delete(&mut self, name: &str) -> Result<BackupStatus, VaultError> {
        self.reload()?;
        self.ready_for_change()?;
        let before = self.doc.records.len();
        self.doc.records.retain(|record| record.name != name);
        if self.doc.records.len() == before {
            return Err(VaultError::UnknownSecret(name.into()));
        }
        self.commit(AuditEvent::named("delete", name, "ok"))
    }

    /// Decrypts the newest local backup with the check key and compares it with the vault (R19).
    pub fn check_newest(&self) -> Result<BackupCheck, VaultError> {
        backup::check_newest(&self.doc, &self.paths.local_backups)
    }

    /// The newest local backup's path and ciphertext.
    pub fn read_newest(&self) -> Result<(PathBuf, Vec<u8>), VaultError> {
        backup::read_newest(&self.doc, &self.paths.local_backups)
    }

    pub fn mirror_dir(&self) -> &str {
        &self.doc.mirror_dir
    }

    pub fn generation(&self) -> u64 {
        self.doc.generation
    }

    /// Removes this Mac's vault so a backup can be restored into a fresh one (R20). Needs the
    /// recovery key, and only goes ahead when the newest backup opens with it and matches the
    /// vault, so nothing is lost. Keeps the backups and the audit log.
    /// After this the caller drops the vault.
    pub fn reset(&mut self, typed: Option<SecretValue>) -> Result<ResetOutcome, VaultError> {
        self.reload()?;
        if self.is_unused() {
            drop(typed);
            return self.remove_unused();
        }
        let Some(typed) = typed else {
            let _ = self.audit(AuditEvent::new("reset", "denied: no recovery key"));
            return Err(VaultError::WrongRecoveryKey);
        };
        let identity = backup::parse_identity(&typed);
        drop(typed);
        let (file, data) = self.read_newest()?;
        let check = backup::parse_identity(&self.doc.check_identity)?;
        let payload = backup::open_bytes(&data, &check)?;
        let matches_vault = payload.vault_id == self.doc.vault_id
            && payload.recovery_recipient == self.doc.recovery_recipient
            && same_records(&payload.records, &self.doc.records);
        let proven = identity.is_ok_and(|id| {
            backup::public_of(&id) == self.doc.recovery_recipient && backup::open_bytes(&data, &id).is_ok()
        });
        if !proven {
            let _ = self.audit(AuditEvent::new("reset", "denied: wrong recovery key"));
            return Err(VaultError::WrongRecoveryKey);
        }
        if !matches_vault {
            let _ = self.audit(AuditEvent::new("reset", "denied: newest backup differs from vault"));
            return Err(VaultError::BackupMismatch);
        }
        // A copy of the backup just proven, in the vault folder, so `vault restore` needs no
        // file from the person. Ciphertext only.
        store::write_atomic(&self.paths.restore_point, &data)?;
        let info = RestorePointInfo { mirror_dir: self.doc.mirror_dir.clone(), file: file.display().to_string() };
        let info = serde_json::to_vec(&info).map_err(|_| VaultError::Io("restore point encoding".into()))?;
        store::write_atomic(&self.paths.restore_point_info, &info)?;
        let mut event = AuditEvent::new("reset", "ok");
        event.detail = Some(format!(
            "vault removed (vault file and key file); newest backup {} kept as the restore point",
            file.display()
        ));
        self.audit(event)?;
        keyprotect::remove(&self.paths.dir)?;
        fs::remove_file(&self.paths.vault_file)?;
        Ok(ResetOutcome { unused: false, newest_file: Some(file.display().to_string()), kit_path: None })
    }

    /// Removes a vault that never held a secret: the kit isn't confirmed, so nothing could be
    /// stored (R20). Anyone who could do this could already read the unconfirmed kit.
    fn remove_unused(&mut self) -> Result<ResetOutcome, VaultError> {
        let mut event = AuditEvent::new("reset", "ok");
        event.detail = Some("unused vault removed (kit not confirmed, no secrets)".into());
        self.audit(event)?;
        keyprotect::remove(&self.paths.dir)?;
        fs::remove_file(&self.paths.vault_file)?;
        Ok(ResetOutcome { unused: true, newest_file: None, kit_path: self.doc.kit_path.clone() })
    }

    /// What `vault status` shows about the open vault. Information only.
    pub fn status(&self) -> OpenedStatus {
        let doc = &self.doc;
        let mut by_kind = Vec::new();
        for kind in [Kind::ApiKey, Kind::Login, Kind::TwoFactor] {
            by_kind.push((kind, doc.records.iter().filter(|r| r.kind == kind).count()));
        }
        let log = &self.paths.audit_log;
        let chain = audit::read_and_verify(log).and_then(|(lines, _)| {
            if audit::chain_contains(log, &doc.audit_head)? {
                Ok(lines)
            } else {
                Err(VaultError::AuditChainBroken(0))
            }
        });
        let (audit_lines, audit_problem, recent_changes) = match chain {
            Ok(lines) => {
                let recent = lines
                    .iter()
                    .rev()
                    .filter(|l| matches!(l.event.event.as_str(), "add" | "delete" | "restore" | "confirm-kit" | "init" | "reset"))
                    .take(5)
                    .map(|l| format!("{}  {} {}", l.t, l.event.event, l.event.name.clone().unwrap_or_default()))
                    .collect();
                (Some(lines.len()), None, recent)
            }
            Err(error) => (None, Some(error.to_string()), Vec::new()),
        };
        OpenedStatus {
            vault_id: doc.vault_id.clone(),
            created_at: doc.created_at.clone(),
            recovery_fingerprint: backup::fingerprint(&doc.recovery_recipient),
            kit_confirmed: doc.kit_confirmed,
            kit_path: doc.kit_path.clone(),
            mirror_dir: doc.mirror_dir.clone(),
            generation: doc.generation,
            secrets: doc.records.len(),
            by_kind,
            last_backup: doc.last_backup.clone(),
            audit_lines,
            audit_problem,
            recent_changes,
        }
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

/// The audit log for `vault audit`, its chain checked (R29). Lines hold no values (R28).
pub fn audit_report(paths: &Paths, all: bool) -> AuditReply {
    match audit::read_and_verify(&paths.audit_log) {
        Ok((lines, _)) => {
            let total = lines.len();
            let skip = if all { 0 } else { total.saturating_sub(25) };
            AuditReply { ok: true, total, lines: lines.into_iter().skip(skip).collect(), problem: None }
        }
        Err(error) => AuditReply { ok: true, total: 0, lines: Vec::new(), problem: Some(error.to_string()) },
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RestorePointInfo {
    mirror_dir: String,
    file: String,
}

/// Whether `vault reset` left a restore point on this Mac.
pub fn has_restore_point(paths: &Paths) -> bool {
    paths.restore_point.is_file()
}

/// Restores a backup into an empty vault on this Mac, with the recovery key (R20). The backup is
/// the file the person named, or the restore point `vault reset` kept. Makes a new vault key and
/// a new vault id. The restored vault starts its own line of backups.
pub fn restore(
    paths: &Paths,
    file: Option<(String, Vec<u8>)>,
    default_mirror_dir: &Path,
    typed: SecretValue,
) -> Result<(Vault, RestoreReport), VaultError> {
    if store::vault_exists(paths) || keyprotect::key_exists(&paths.dir) {
        return Err(VaultError::AlreadyInitialized);
    }
    let from_restore_point = file.is_none();
    let (source, data, mirror_dir) = match file {
        Some((source, data)) => (source, data, default_mirror_dir.display().to_string()),
        None => {
            let info: RestorePointInfo = fs::read(&paths.restore_point_info)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .ok_or(VaultError::NoBackup)?;
            let data = fs::read(&paths.restore_point).map_err(|_| VaultError::NoBackup)?;
            (info.file, data, info.mirror_dir)
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
        mirror_dir,
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
    if from_restore_point {
        let _ = fs::remove_file(&paths.restore_point);
        let _ = fs::remove_file(&paths.restore_point_info);
    }
    let vault = Vault { paths: paths.clone(), key, doc };
    Ok((
        vault,
        RestoreReport { vault_id, from_vault_id: payload.vault_id, secrets, from_generation: payload.generation },
    ))
}

impl Vault {
    /// The first backup of a vault the daemon just restored or opened.
    pub fn backup_if_needed(&mut self) -> Option<BackupStatus> {
        if self.needs_backup() { Some(self.backup_now()) } else { None }
    }
}
