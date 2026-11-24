//! The vault's operations. They run only in the daemon (a LaunchAgent in the owner's login on
//! macOS, a systemd user service on Linux) and in `vault install` for the first vault (R13). The command-line tool
//! never opens the vault; it asks the daemon. Nothing here returns a secret value: results are
//! summaries, codes, statuses and reports (R4).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::audit::{self, AuditEvent};
use crate::backup;
use crate::details;
use crate::error::VaultError;
use crate::keyprotect;
use crate::kinds::{self, Renewed};
use crate::model::{self, BackupStatus, Handover, Kind, Record, SecretRef, SecretSummary, VAULT_FORMAT, VaultDoc};
use crate::protocol::{BackupCheck, OpenedStatus};
use crate::rules::{Placement, ProxyRule};
use crate::secret::SecretValue;
use crate::store::{self, Paths};
use crate::totp::{self, TotpCode};
use crate::wallet::{self, Cancel, CancelArgs, Caps, Chain, Payment, SignArgs, WalletInfo};

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
    /// Empty for a kind with a default site (a Claude plan), which then gets it.
    pub site: String,
    pub rule: Option<ProxyRule>,
    pub username: Option<String>,
    /// For a 2FA seed: the base32 seed or the otpauth link.
    pub value: SecretValue,
    /// An app secret only: the application it belongs to (required for one).
    pub app: Option<String>,
    /// An app secret only: it may be leased to builds (`lease`).
    pub leasable: bool,
}

/// What `sign` made: the payment as checked, its first transaction and (Ethereum) its ladder,
/// signed, and what it counted against the caps.
pub struct SignOutcome {
    pub summary: SecretSummary,
    pub payment: Payment,
    pub signatures: wallet::Signatures,
    pub counted: wallet::Counted,
    pub backup: BackupStatus,
}

/// What a cancel made (#7491): the cancel as checked, its first transaction and its ladder,
/// signed, and what it counted against the daily fee cap.
pub struct CancelOutcome {
    pub summary: SecretSummary,
    pub cancel: Cancel,
    pub signed: crate::evm::Signed,
    pub ladder: Vec<(wallet::Fees, crate::evm::Signed)>,
    pub counted: wallet::Counted,
    pub backup: BackupStatus,
}

pub struct InitReport {
    pub vault_id: String,
    pub vault_identity: String,
    pub recovery_fingerprint: String,
    /// How the vault key is kept (`keyprotect::protect`).
    pub key_protection: String,
    pub kit_path: PathBuf,
    pub mirror_dir: PathBuf,
}

pub struct RestoreReport {
    pub vault_id: String,
    pub vault_identity: String,
    pub from_vault_id: String,
    /// The backup's format; a format-1 backup's secrets got their ids in this restore.
    pub from_format: u32,
    pub secrets: Vec<SecretSummary>,
    pub from_generation: u64,
}

/// What `import_plan` did with one plan.
pub enum ImportOutcome {
    /// Added, or its value replaced (the version it has now).
    Done(u64),
    /// Already there with the same value.
    Unchanged(u64),
    Failed(VaultError),
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
/// kit stays in the owner's home folder until he stashes it. Then the key is protected as well as
/// this machine allows (`keyprotect::protect`: sealed to the TPM on Linux when there is one).
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
        intake_identity: Some(backup::new_identity().0),
        audit_head: audit::GENESIS.into(),
        generation: 1,
        last_backup: None,
        records: Vec::new(),
    };
    let mut event = AuditEvent::new("init", "ok");
    event.detail = Some(format!("vault {vault_id}, recovery key {fingerprint}"));
    doc.audit_head = audit_event(paths, event)?;
    store::save(paths, &key, &doc)?;
    let key_protection = keyprotect::protect(&paths.dir, &key);
    Ok(InitReport {
        vault_identity: model::vault_identity(&doc.recovery_recipient),
        key_protection,
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
         If your {machine} is lost, this key plus a backup file brings the vault back on another\n\
         {machine}: `vault install --for-restore`, then\n\
         `vault restore <backup file>`. Backups are standard age files, so\n\
         `age -d -i <file holding this key> <backup>` also opens them without Volgenic.\n\
         Nobody else, Volgenic included, can open your backups. Lose this key and a dead\n\
         {machine} means the secrets are gone.\n",
        machine = crate::platform::MACHINE,
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
    /// Opens the vault: reads the vault key, then decrypts the vault file. A vault file in an
    /// older format is migrated here, as a change of its own: every secret gets its id, and the
    /// file and a new backup are written in the current format (read old, write new). The
    /// returned text says what the migration did, for the daemon's log.
    pub fn open(paths: &Paths) -> Result<(Vault, Option<String>), VaultError> {
        if !store::vault_exists(paths) {
            return Err(VaultError::NotInitialized);
        }
        let key = keyprotect::load(&paths.dir)?;
        let doc = store::load(paths, &key)?;
        let from = doc.format;
        let mut vault = Vault { paths: paths.clone(), key, doc };
        let given = model::migrate(&mut vault.doc, store::new_random_id)?;
        let made_intake = model::ensure_intake(&mut vault.doc);
        if given.is_none() && !made_intake {
            return Ok((vault, None));
        }
        let what = format!(
            "{} secrets given ids{}",
            given.unwrap_or(0),
            if made_intake { ", intake key made" } else { "" }
        );
        let mut event = AuditEvent::new("migrate", "ok");
        event.detail = Some(format!("vault file format {from} to {VAULT_FORMAT}: {what}"));
        let note = match vault.commit(event) {
            Ok(backup) => format!(
                "migrated the vault file from format {from} to {VAULT_FORMAT} ({what}); backup generation {} OK",
                backup.generation
            ),
            // The migrated file is on disk; a failed backup is the alarm of R19, as for any change.
            Err(error) => format!("migrated the vault file from format {from} to {VAULT_FORMAT}, but {error}"),
        };
        Ok((vault, Some(note)))
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
        self.put(new, false).map(|(summary, status, _)| (summary, status))
    }

    /// Stores a secret, or with `replace`, replaces the value (and rule, site or username) of the
    /// secret already stored under that name, which must be of the same kind: its id stays, and
    /// its version goes up by one. Returns whether it replaced one (`add_sealed`, R40).
    pub fn put(&mut self, new: NewSecret, replace: bool) -> Result<(SecretSummary, BackupStatus, bool), VaultError> {
        self.put_as(new, replace, None)
    }

    /// The default length of a generated password: about 123 bits.
    pub const GENERATED_LENGTH: usize = 20;

    /// Stores a new login whose password the vault makes itself (`generate_login`, R38, #7663),
    /// through `add`'s checks, backup and audit, under its own `generate-login` line. The site is
    /// stored as the host it names, and must have a registrable domain, so the login can be
    /// filled. A name already in the vault is refused (`name_taken`). No value is answered.
    pub fn generate_login(
        &mut self,
        name: &str,
        site: &str,
        username: &str,
        length: Option<usize>,
    ) -> Result<(SecretSummary, BackupStatus), VaultError> {
        let length = length.unwrap_or(Self::GENERATED_LENGTH);
        if !(12..=128).contains(&length) {
            return Err(VaultError::BadRequest("length is 12 to 128 characters".into()));
        }
        let site = crate::sites::normalize_new_site(site)?;
        let new = NewSecret {
            name: name.to_string(),
            kind: Kind::Login,
            site,
            rule: None,
            username: Some(username.to_string()),
            app: None,
            leasable: false,
            value: SecretValue::random_password(length)?,
        };
        let made = format!("password of {length} characters made by the vault");
        self.put_as(new, false, Some(("generate-login", made))).map(|(summary, status, _)| (summary, status))
    }

    /// `put`, with the audit line's event and an addition to its detail when the caller names them.
    fn put_as(
        &mut self,
        new: NewSecret,
        replace: bool,
        event_as: Option<(&str, String)>,
    ) -> Result<(SecretSummary, BackupStatus, bool), VaultError> {
        self.reload()?;
        self.ready_for_change()?;
        let name = new.name.clone();
        let existing = self.doc.records.iter().position(|record| record.name == name);
        let replaced = match existing {
            Some(_) if !replace => return Err(VaultError::NameTaken(new.name)),
            Some(index) if self.doc.records[index].kind != new.kind => return Err(VaultError::WrongKind),
            Some(index) => {
                let mut record = self.new_record(new)?;
                let old = &self.doc.records[index];
                record.id = old.id.clone();
                record.version = old.version + 1;
                record.created_at = old.created_at.clone();
                self.doc.records[index] = record;
                true
            }
            None => {
                let record = self.new_record(new)?;
                self.doc.records.push(record);
                false
            }
        };
        self.check_fits()?;
        let record = self.doc.find(&name).ok_or(VaultError::VaultFileCorrupt)?;
        let summary = record.summary();
        let (event_name, detail) = match event_as {
            Some((event_name, more)) => (event_name, format!("{}; {more}", describe(record))),
            None => (if replaced { "replace" } else { "add" }, describe(record)),
        };
        let mut event = AuditEvent::named(event_name, &record.name, "ok");
        event.secret_id = Some(record.id.clone());
        event.detail = Some(detail);
        let status = self.commit(event)?;
        Ok((summary, status, replaced))
    }

    /// Checks a new secret as the person (or a sealed value) gave it, and makes its record with
    /// a fresh id and version 1 (R5, R7). Whether the name is free is the caller's check.
    fn new_record(&mut self, new: NewSecret) -> Result<Record, VaultError> {
        model::validate_name(&new.name)?;
        // A wallet's key is made by the vault itself (`create_wallet`) and never given to it.
        if new.kind == Kind::Wallet {
            return Err(VaultError::InvalidSecret(
                "the vault makes a wallet's key itself and never takes one: `vault wallet create`".into(),
            ));
        }
        let spec = kinds::spec(new.kind);
        // An app secret names its application; nothing else has one or may be leased (#7446).
        let app = match (new.kind, &new.app) {
            (Kind::AppSecret, Some(app)) => {
                model::validate_app(app)?;
                Some(app.clone())
            }
            (Kind::AppSecret, None) => {
                return Err(VaultError::InvalidSecret("an app secret needs the application it belongs to".into()));
            }
            (_, Some(_)) => {
                return Err(VaultError::InvalidSecret("only an app_secret belongs to an application".into()));
            }
            (_, None) => None,
        };
        if new.leasable && new.kind != Kind::AppSecret {
            return Err(VaultError::InvalidSecret("only an app_secret may be leased to builds".into()));
        }
        let site = match (new.site.is_empty(), new.kind.default_site(), &app) {
            (true, Some(default), _) => default.to_string(),
            (true, None, Some(app)) => app.clone(),
            _ => new.site.clone(),
        };
        model::validate_site(&site)?;
        if new.value.is_empty() || new.value.len() > 16 * 1024 {
            return Err(VaultError::InvalidSecret("the value must be 1 byte to 16 KiB".into()));
        }
        // A login's auth.json becomes the vault's own stored form (`logins`).
        let (new_value, expires_at) = match spec.and_then(|spec| spec.intake) {
            Some(intake) => intake(&new.value)?,
            None => (new.value, None),
        };
        let new = NewSecret { value: new_value, ..new };
        let (value, totp_params, fields) = match new.kind {
            Kind::TwoFactor => {
                let (seed, params) = totp::parse_seed_input(&new.value)?;
                (seed, Some(params), None)
            }
            // Personal details are stored as the vault's own object, with the filled fields named.
            Kind::PersonalDetails => {
                let (stored, fields) = details::intake(&new.value)?;
                details::validate(&stored)?;
                (stored, None, Some(fields))
            }
            _ => (new.value, None, None),
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
        if let Some(spec) = spec {
            (spec.validate)(&value)?;
        }
        if new.kind == Kind::AppSecret {
            crate::lease::validate_value(&value)?;
        }
        let mut id = store::new_random_id()?;
        while self.doc.records.iter().any(|record| record.id == id) {
            id = store::new_random_id()?;
        }
        let created_at = crate::now_rfc3339();
        Ok(Record {
            id,
            version: 1,
            name: new.name,
            kind: new.kind,
            site,
            updated_at: Some(created_at.clone()),
            created_at,
            rule: if new.kind == Kind::ApiKey { new.rule } else { None },
            username: if new.kind == Kind::Login { new.username } else { None },
            totp: totp_params,
            expires_at,
            // A login the vault renews arrives claimed: a new sign-in (sealed) or one a person
            // typed in is the vault's alone. An import says otherwise (`import_logins`).
            handover: spec.and_then(|spec| spec.refresher).map(|_| Handover {
                claimed: true,
                claimed_at: Some(crate::now_rfc3339()),
                imported: None,
            }),
            fields,
            leasable: if new.kind == Kind::AppSecret { Some(new.leasable) } else { None },
            app,
            wallet: None,
            value,
        })
    }

    /// Checks a recovery key the person typed against this vault's (R16): the gate for what only
    /// the person on this machine may do, since the socket can't tell them from an agent (R23).
    fn check_recovery_key(&self, typed: SecretValue, op: &str, name: &str) -> Result<(), VaultError> {
        let identity = backup::parse_identity(&typed);
        drop(typed);
        let matches = identity.as_ref().is_ok_and(|id| backup::public_of(id) == self.doc.recovery_recipient);
        if matches {
            Ok(())
        } else {
            let _ = self.audit(AuditEvent::named(op, name, "denied: wrong recovery key"));
            Err(VaultError::WrongRecoveryKey)
        }
    }

    /// Makes a wallet (#7440): a new key from the operating system's random numbers, kept as
    /// the record's value and never given out; its address and the caps the person set. Needs
    /// the recovery key, because the caps are the person's alone to set.
    pub fn create_wallet(
        &mut self,
        name: &str,
        chain: Chain,
        caps: Caps,
        recovery_key: SecretValue,
    ) -> Result<(SecretSummary, BackupStatus), VaultError> {
        self.reload()?;
        self.ready_for_change()?;
        self.check_recovery_key(recovery_key, "wallet-create", name)?;
        model::validate_name(name)?;
        caps.validate(chain)?;
        if self.doc.find(name).is_some() {
            return Err(VaultError::NameTaken(name.into()));
        }
        let (key, address) = wallet::new_key(chain)?;
        let mut id = store::new_random_id()?;
        while self.doc.records.iter().any(|record| record.id == id) {
            id = store::new_random_id()?;
        }
        let created_at = crate::now_rfc3339();
        self.doc.records.push(Record {
            id,
            version: 1,
            name: name.to_string(),
            kind: Kind::Wallet,
            site: chain.label().to_string(),
            updated_at: Some(created_at.clone()),
            created_at,
            rule: None,
            username: None,
            totp: None,
            expires_at: None,
            handover: None,
            fields: None,
            app: None,
            leasable: None,
            wallet: Some(WalletInfo { chain, address, caps, spends: Vec::new() }),
            value: key,
        });
        self.check_fits()?;
        let record = self.doc.find(name).ok_or(VaultError::VaultFileCorrupt)?;
        let summary = record.summary();
        let mut event = AuditEvent::named("wallet-create", name, "ok");
        event.secret_id = Some(record.id.clone());
        event.detail = Some(describe(record));
        let status = self.commit(event)?;
        Ok((summary, status))
    }

    /// Changes a wallet's caps: only with the recovery key. Its key, address and the last day's
    /// payments stay; its version goes up by one.
    pub fn set_wallet_caps(
        &mut self,
        secret: &SecretRef,
        caps: Caps,
        recovery_key: SecretValue,
    ) -> Result<(SecretSummary, BackupStatus), VaultError> {
        self.reload()?;
        self.ready_for_change()?;
        let label = self.doc.find_ref(secret).map(|record| record.name.clone()).unwrap_or_else(|| secret.label());
        self.check_recovery_key(recovery_key, "wallet-caps", &label)?;
        let record = match secret {
            SecretRef::Name(name) => self.doc.records.iter_mut().find(|record| &record.name == name),
            SecretRef::Id(id) => self.doc.records.iter_mut().find(|record| &record.id == id),
        }
        .ok_or_else(|| secret.not_found())?;
        let info = record.wallet.as_mut().filter(|_| record.kind == Kind::Wallet).ok_or(VaultError::WrongKind)?;
        caps.validate(info.chain)?;
        let before = info.caps;
        let chain = info.chain;
        info.caps = caps;
        record.version += 1;
        record.updated_at = Some(crate::now_rfc3339());
        let summary = record.summary();
        let mut event = AuditEvent::named("wallet-caps", &summary.name, "ok");
        event.secret_id = Some(summary.id.clone());
        event.detail = Some(format!("caps were {}; now {}", before.describe(chain), caps.describe(chain)));
        let status = self.commit(event)?;
        Ok((summary, status))
    }

    /// `sign` (#7440): checks the transfer against the wallet and its caps, signs it and its
    /// ladder, and records the payment in the wallet's last day, as one change whose audit line
    /// (`sign`: chain, token, amount, recipient, nonce, fees, hash, the caller) is on disk before
    /// anything is returned (R28). `stamp` adds the caller's hint to that line. The ladder's own
    /// line is the caller's (`server`), after this.
    pub fn sign_payment(
        &mut self,
        secret: &SecretRef,
        args: &SignArgs<'_>,
        stamp: impl Fn(AuditEvent) -> AuditEvent,
    ) -> Result<SignOutcome, VaultError> {
        self.reload()?;
        self.ready_for_change()?;
        let now = crate::now_unix();
        let now_ms = crate::now_unix_ms();
        let index = self.doc.records.iter().position(|record| match secret {
            SecretRef::Name(name) => &record.name == name,
            SecretRef::Id(id) => &record.id == id,
        });
        let record = &self.doc.records[index.ok_or_else(|| secret.not_found())?];
        let info = record.wallet.as_ref().filter(|_| record.kind == Kind::Wallet).ok_or(VaultError::WrongKind)?;
        let payment = wallet::check(info, args, now_ms)?;
        let counted = wallet::decide(info, &payment, now)?;
        let signatures = wallet::sign(info, &payment, &record.value)?;
        let family = info.chain.family();
        let index = index.ok_or(VaultError::VaultFileCorrupt)?;
        let record = &mut self.doc.records[index];
        if let Some(info) = record.wallet.as_mut() {
            wallet::record(info, &payment, counted, now)?;
        }
        self.check_fits()?;
        let record = &self.doc.records[index];
        let summary = record.summary();
        let mut event = AuditEvent::named("sign", &record.name, "ok");
        event.secret_id = Some(record.id.clone());
        event.detail = Some(format!(
            "{}; hash {}; {}",
            payment.describe(),
            signatures.first.hash,
            match (counted.replaces, &payment.plan) {
                (Some(_), wallet::Plan::Evm(_)) => format!(
                    "replaces the same transfer at this nonce: no amount counted again, {} more worst-case fees",
                    family.fee_text(counted.fee)
                ),
                (Some(_), _) => "the same transaction asked for again: nothing counted again".to_string(),
                (None, _) => format!(
                    "counted ${} and {} worst-case fees against the daily caps",
                    wallet::decimal(counted.micros as u128, 6),
                    family.fee_text(counted.fee)
                ),
            }
        ));
        let backup = self.commit(stamp(event))?;
        Ok(SignOutcome { summary, payment, signatures, counted, backup })
    }

    /// `sign` with `cancel` (#7491): a 0-ETH transfer from the wallet to itself at the nonce of a
    /// payment it signed in the last day, and its ladder, within the fee caps. One change, whose
    /// `sign-cancel` line (the nonce, the fees, what it cancels, every hash, the caller) is on disk
    /// before anything is returned (R28); `stamp` adds the caller's hint to it.
    pub fn sign_cancel(
        &mut self,
        secret: &SecretRef,
        args: &CancelArgs<'_>,
        stamp: impl Fn(AuditEvent) -> AuditEvent,
    ) -> Result<CancelOutcome, VaultError> {
        self.reload()?;
        self.ready_for_change()?;
        let now = crate::now_unix();
        let index = self
            .doc
            .records
            .iter()
            .position(|record| match secret {
                SecretRef::Name(name) => &record.name == name,
                SecretRef::Id(id) => &record.id == id,
            })
            .ok_or_else(|| secret.not_found())?;
        let record = &self.doc.records[index];
        let info = record.wallet.as_ref().filter(|_| record.kind == Kind::Wallet).ok_or(VaultError::WrongKind)?;
        let cancel = wallet::check_cancel(info, args, now)?;
        let counted = wallet::decide_cancel(info, &cancel, now)?;
        let signed = crate::evm::sign(&cancel.tx(cancel.first), &record.value, &cancel.address)?;
        let mut ladder = Vec::with_capacity(cancel.ladder.len());
        for fees in &cancel.ladder {
            ladder.push((*fees, crate::evm::sign(&cancel.tx(*fees), &record.value, &cancel.address)?));
        }
        let record = &mut self.doc.records[index];
        if let Some(info) = record.wallet.as_mut() {
            wallet::record_cancel(info, &cancel, counted, now);
        }
        self.check_fits()?;
        let record = &self.doc.records[index];
        let summary = record.summary();
        let mut event = AuditEvent::named("sign-cancel", &record.name, "ok");
        event.secret_id = Some(record.id.clone());
        let ladder_text = if ladder.is_empty() {
            String::new()
        } else {
            format!(
                "; {} replacement(s) up to {} gwei/gas, hashes {}",
                ladder.len(),
                wallet::decimal(cancel.top().max_fee_per_gas as u128, 9),
                ladder.iter().map(|(_, signed)| format!("0x{}", hex::encode(signed.hash))).collect::<Vec<_>>().join(", ")
            )
        };
        event.detail = Some(format!(
            "{}; hash 0x{}{}; worst-case fee {} ETH, {} ETH more counted against the daily fee cap",
            cancel.describe(),
            hex::encode(signed.hash),
            ladder_text,
            wallet::decimal(cancel.worst_fee_wei() as u128, 18),
            wallet::decimal(counted.fee as u128, 18)
        ));
        let backup = self.commit(stamp(event))?;
        Ok(CancelOutcome { summary, cancel, signed, ladder, counted, backup })
    }

    /// Every backup must stay small enough for `vault restore FILE` to take back. Measured
    /// exactly, with the change in place; 4 KiB covers what the next commit changes (the audit
    /// head, the generation, the timestamp). A change that doesn't fit is dropped: the vault goes
    /// back to what is on disk.
    fn check_fits(&mut self) -> Result<(), VaultError> {
        let measured = backup::plaintext_size(&self.doc, &self.doc.records);
        if measured.as_ref().map_or(true, |size| size.saturating_add(4096) > backup::MAX_VAULT_PLAINTEXT) {
            self.reload()?;
            return Err(match measured {
                Err(e) => e,
                Ok(_) => VaultError::InvalidSecret(format!(
                    "the vault is full: its backup would pass {} MiB, the most a restore takes",
                    backup::MAX_VAULT_PLAINTEXT / (1024 * 1024)
                )),
            });
        }
        Ok(())
    }

    /// Imports the host's existing Claude plan tokens on an upgrade (R41), in one change: a plan
    /// not stored yet is added, one stored with the same value is left alone, one stored with a
    /// different value gets the new value and its version goes up. A name held by another kind
    /// fails, and the others go ahead. Safe to repeat. Each plan's result is by name only.
    pub fn import_plans(
        &mut self,
        plans: Vec<(String, SecretValue)>,
    ) -> Result<(Vec<(String, ImportOutcome)>, Option<BackupStatus>), VaultError> {
        self.reload()?;
        self.ready_for_change()?;
        let mut results = Vec::with_capacity(plans.len());
        let mut changed = Vec::new();
        for (name, value) in plans {
            let outcome = match self.import_one(&name, value) {
                Ok((outcome, change)) => {
                    if let Some(change) = change {
                        changed.push(change);
                    }
                    outcome
                }
                Err(error) => ImportOutcome::Failed(error),
            };
            results.push((name, outcome));
        }
        if changed.is_empty() {
            return Ok((results, None));
        }
        self.check_fits()?;
        for (name, id, what) in &changed {
            let mut event = AuditEvent::named("import-plan", name, "ok");
            event.secret_id = Some(id.clone());
            event.detail = Some(what.clone());
            self.audit(event)?;
        }
        let mut event = AuditEvent::new("import-plan", "ok");
        event.detail = Some(format!("{} of {} plans added or replaced", changed.len(), results.len()));
        let status = self.commit(event)?;
        Ok((results, Some(status)))
    }

    /// One plan of an import: its outcome, and what changed (name, id, a description) if anything.
    fn import_one(
        &mut self,
        name: &str,
        value: SecretValue,
    ) -> Result<(ImportOutcome, Option<(String, String, String)>), VaultError> {
        model::validate_name(name)?;
        (kinds::CLAUDE_PLAN.validate)(&value)?;
        match self.doc.records.iter().position(|record| record.name == name) {
            None => {
                let new = NewSecret {
                    name: name.to_string(),
                    kind: Kind::ClaudePlan,
                    site: String::new(),
                    rule: None,
                    username: None,
                    value,
                    app: None,
                    leasable: false,
                };
                let record = self.new_record(new)?;
                let change = (record.name.clone(), record.id.clone(), "claude_plan added".to_string());
                self.doc.records.push(record);
                Ok((ImportOutcome::Done(1), Some(change)))
            }
            Some(index) => {
                let record = &mut self.doc.records[index];
                if record.kind != Kind::ClaudePlan {
                    return Err(VaultError::NameTaken(name.to_string()));
                }
                if record.value.same_as(&value) {
                    return Ok((ImportOutcome::Unchanged(record.version), None));
                }
                record.value = value;
                record.version += 1;
                record.updated_at = Some(crate::now_rfc3339());
                let change = (record.name.clone(), record.id.clone(), format!("value replaced, version {}", record.version));
                Ok((ImportOutcome::Done(record.version), Some(change)))
            }
        }
    }

    /// Stores what a kind's refresher renewed (token upkeep): a new version of the same secret,
    /// written to the vault file before the caller uses the new token. Only onto version `seen`,
    /// the one that was renewed: if the secret changed meanwhile (a new sign-in replaced it), the
    /// renewal belongs to a value no longer stored and is dropped (`VersionMismatch`).
    ///
    /// No `ready_for_change` check: the provider has already retired the old refresh token, so
    /// not storing the new one would lose the login. A failed backup is still the alarm of R19.
    pub fn renew(&mut self, id: &str, seen: u64, renewed: Renewed) -> Result<(SecretSummary, Result<BackupStatus, VaultError>), VaultError> {
        self.reload()?;
        let record = self.doc.records.iter_mut().find(|record| record.id == id).ok_or_else(|| VaultError::UnknownSecret(format!("id {id}")))?;
        if record.version != seen {
            return Err(VaultError::VersionMismatch(record.version));
        }
        record.value = renewed.value;
        record.expires_at = renewed.expires_at;
        record.version += 1;
        record.updated_at = Some(crate::now_rfc3339());
        let summary = record.summary();
        let mut event = AuditEvent::named("renew", &summary.name, "ok");
        event.secret_id = Some(summary.id.clone());
        event.detail = Some(format!("renewed by the vault, version {}", summary.version));
        self.doc.generation += 1;
        self.doc.audit_head = self.audit(event)?;
        store::save(&self.paths, &self.key, &self.doc)?;
        let status = self.backup_now();
        let backup = if status.ok { Ok(status) } else { Err(VaultError::BackupFailed(status.detail)) };
        Ok((summary, backup))
    }

    /// Imports the host's existing Codex and Grok logins (`auth.json`, whole) on an upgrade
    /// (#7380), in one change. Each login is stored *unclaimed*: the vault uses its access token
    /// but never renews it until `claim_refresh`, because the host's daemon may still be renewing
    /// it. By name:
    ///
    /// - not stored yet: added, unclaimed (`done`, version 1);
    /// - stored, and this is the `auth.json` the last import stored (whatever the vault did with
    ///   it since): `unchanged`;
    /// - stored, unclaimed, a different `auth.json` (the daemon renewed it meanwhile): replaced,
    ///   version up, still unclaimed (`done`);
    /// - stored and claimed, a different `auth.json`: `failed` with `login_claimed`. The vault
    ///   renews it now, so a file's tokens are older than the vault's and may be dead; only a new
    ///   sign-in (`add_sealed` with `replace`) replaces it;
    /// - a name held by another kind: `failed`, and the others go ahead.
    pub fn import_logins(
        &mut self,
        logins: Vec<(String, Kind, SecretValue)>,
    ) -> Result<(Vec<(String, Kind, ImportOutcome, bool)>, Option<BackupStatus>), VaultError> {
        self.reload()?;
        self.ready_for_change()?;
        let mut results = Vec::with_capacity(logins.len());
        let mut changed = Vec::new();
        for (name, kind, given) in logins {
            let outcome = match self.import_login(&name, kind, given) {
                Ok((outcome, change)) => {
                    if let Some(change) = change {
                        changed.push(change);
                    }
                    outcome
                }
                Err(error) => ImportOutcome::Failed(error),
            };
            let claimed = self.doc.find(&name).filter(|record| record.kind == kind).and_then(|record| record.handover.as_ref()).is_some_and(|h| h.claimed);
            results.push((name, kind, outcome, claimed));
        }
        if changed.is_empty() {
            return Ok((results, None));
        }
        self.check_fits()?;
        for (name, id, what) in &changed {
            let mut event = AuditEvent::named("import-login", name, "ok");
            event.secret_id = Some(id.clone());
            event.detail = Some(what.clone());
            self.audit(event)?;
        }
        let mut event = AuditEvent::new("import-login", "ok");
        event.detail = Some(format!("{} of {} logins added or replaced, unclaimed", changed.len(), results.len()));
        let status = self.commit(event)?;
        Ok((results, Some(status)))
    }

    fn import_login(
        &mut self,
        name: &str,
        kind: Kind,
        given: SecretValue,
    ) -> Result<(ImportOutcome, Option<(String, String, String)>), VaultError> {
        model::validate_name(name)?;
        let spec = kinds::spec(kind).filter(|spec| spec.refresher.is_some()).ok_or(VaultError::WrongKind)?;
        let intake = spec.intake.ok_or(VaultError::WrongKind)?;
        let (stored, expires_at) = intake(&given)?;
        (spec.validate)(&stored)?;
        let digest = crate::logins::digest(&stored);
        let unclaimed = Handover { claimed: false, claimed_at: None, imported: Some(digest.clone()) };
        match self.doc.records.iter().position(|record| record.name == name) {
            None => {
                drop(stored);
                // `new_record` reads the auth.json again, into the same stored form.
                let mut record = self.new_record(NewSecret {
                    name: name.to_string(),
                    kind,
                    site: String::new(),
                    rule: None,
                    username: None,
                    value: given,
                    app: None,
                    leasable: false,
                })?;
                record.handover = Some(unclaimed);
                let change = (record.name.clone(), record.id.clone(), format!("{} added, unclaimed", kind.label()));
                self.doc.records.push(record);
                Ok((ImportOutcome::Done(1), Some(change)))
            }
            Some(index) => {
                drop(given);
                let record = &mut self.doc.records[index];
                if record.kind != kind {
                    return Err(VaultError::NameTaken(name.to_string()));
                }
                let handover = record.handover.clone().unwrap_or(Handover { claimed: true, claimed_at: None, imported: None });
                if handover.imported.as_deref() == Some(digest.as_str()) {
                    return Ok((ImportOutcome::Unchanged(record.version), None));
                }
                if handover.claimed {
                    return Err(VaultError::LoginClaimed(name.to_string()));
                }
                record.value = stored;
                record.expires_at = expires_at;
                record.handover = Some(unclaimed);
                record.version += 1;
                record.updated_at = Some(crate::now_rfc3339());
                let change = (record.name.clone(), record.id.clone(), format!("value replaced, version {}, unclaimed", record.version));
                Ok((ImportOutcome::Done(record.version), Some(change)))
            }
        }
    }

    /// The host's daemon says it has stopped renewing an imported login (`claim_refresh`): from
    /// now on the vault alone renews it. Only onto `version`, the one the daemon's import stored
    /// (`import_login`'s reply): a different version means the vault holds another `auth.json`
    /// than the one the daemon handed over, and nothing is claimed (`version_mismatch`; import the
    /// file again, then claim that). Claiming a login already claimed changes nothing. Returns the
    /// secret, whether it was claimed already, and the backup of the change.
    pub fn claim_refresh(
        &mut self,
        secret: &SecretRef,
        version: u64,
    ) -> Result<(SecretSummary, bool, Option<BackupStatus>), VaultError> {
        self.reload()?;
        let record = self.doc.find_ref(secret).ok_or_else(|| secret.not_found())?;
        if kinds::spec(record.kind).and_then(|spec| spec.refresher).is_none() {
            return Err(VaultError::WrongKind);
        }
        if record.handover.as_ref().is_none_or(|handover| handover.claimed) {
            return Ok((record.summary(), true, None));
        }
        if record.version != version {
            return Err(VaultError::VersionMismatch(record.version));
        }
        let id = record.id.clone();
        self.ready_for_change()?;
        let record = self.doc.records.iter_mut().find(|record| record.id == id).ok_or(VaultError::VaultFileCorrupt)?;
        let handover = record.handover.get_or_insert(Handover { claimed: false, claimed_at: None, imported: None });
        handover.claimed = true;
        handover.claimed_at = Some(crate::now_rfc3339());
        record.version += 1;
        record.updated_at = Some(crate::now_rfc3339());
        let summary = record.summary();
        let mut event = AuditEvent::named("claim-refresh", &summary.name, "ok");
        event.secret_id = Some(summary.id.clone());
        event.detail = Some(format!(
            "the host's daemon stopped renewing it at version {version}; the vault alone renews it now (version {})",
            summary.version
        ));
        let status = self.commit(event)?;
        Ok((summary, false, Some(status)))
    }

    /// Deletes a secret. Earlier backup generations still hold it (R18).
    pub fn delete(&mut self, secret: &SecretRef) -> Result<BackupStatus, VaultError> {
        self.reload()?;
        self.ready_for_change()?;
        let (name, id) = match self.doc.find_ref(secret) {
            // A wallet's key is the only way to its funds: deleting it isn't a socket request
            // anyone with the owner's user ID can make (#7440). A restore can still bring back a
            // generation without it.
            Some(record) if record.kind == Kind::Wallet => {
                return Err(VaultError::InvalidSecret(
                    "a wallet holds money and its key exists only in this vault, so it isn't deleted".into(),
                ));
            }
            Some(record) => (record.name.clone(), record.id.clone()),
            None => return Err(secret.not_found()),
        };
        self.doc.records.retain(|record| record.id != id);
        let mut event = AuditEvent::named("delete", &name, "ok");
        event.secret_id = Some(id);
        self.commit(event)
    }

    /// Renames a secret. Its id, rule and value stay; its version goes up by one.
    pub fn rename(&mut self, secret: &SecretRef, new_name: &str) -> Result<(SecretSummary, BackupStatus), VaultError> {
        self.reload()?;
        self.ready_for_change()?;
        model::validate_name(new_name)?;
        if self.doc.find(new_name).is_some() {
            return Err(VaultError::NameTaken(new_name.into()));
        }
        let now = crate::now_rfc3339();
        let record = match secret {
            SecretRef::Name(name) => self.doc.records.iter_mut().find(|record| &record.name == name),
            SecretRef::Id(id) => self.doc.records.iter_mut().find(|record| &record.id == id),
        }
        .ok_or_else(|| secret.not_found())?;
        let old_name = std::mem::replace(&mut record.name, new_name.to_string());
        record.version += 1;
        record.updated_at = Some(now);
        let summary = record.summary();
        let mut event = AuditEvent::named("rename", &old_name, "ok");
        event.secret_id = Some(summary.id.clone());
        event.detail = Some(format!("renamed to {new_name:?}, version {}", summary.version));
        let status = self.commit(event)?;
        Ok((summary, status))
    }

    /// Changes where an API key goes (#8940): its header, or its query parameter. Its host, port,
    /// methods and path stay, and so do its id and value; its version goes up by one. Needs the
    /// recovery key: an agent that could choose where the key goes could put it in a field an
    /// endpoint under the rule stores or shows. Returns the placement it had, as `describe` says.
    pub fn set_rule(
        &mut self,
        secret: &SecretRef,
        placement: Placement,
        recovery_key: SecretValue,
    ) -> Result<(SecretSummary, String, BackupStatus), VaultError> {
        self.reload()?;
        self.ready_for_change()?;
        let label = self.doc.find_ref(secret).map(|record| record.name.clone()).unwrap_or_else(|| secret.label());
        self.check_recovery_key(recovery_key, "set-rule", &label)?;
        let record = match secret {
            SecretRef::Name(name) => self.doc.records.iter_mut().find(|record| &record.name == name),
            SecretRef::Id(id) => self.doc.records.iter_mut().find(|record| &record.id == id),
        }
        .ok_or_else(|| secret.not_found())?;
        if record.kind != Kind::ApiKey {
            return Err(VaultError::WrongKind);
        }
        let rule = record.rule.as_ref().ok_or_else(|| VaultError::InvalidRule("this key has no rule".into()))?;
        if rule.placement() == placement {
            return Err(VaultError::InvalidRule(format!("the key already goes there ({})", rule.describe_placement())));
        }
        let was = rule.describe_placement();
        let changed = rule.with_placement(placement);
        let now_placed = changed.describe_placement();
        record.rule = Some(changed);
        record.version += 1;
        record.updated_at = Some(crate::now_rfc3339());
        let summary = record.summary();
        let mut event = AuditEvent::named("set-rule", &summary.name, "ok");
        event.secret_id = Some(summary.id.clone());
        event.detail = Some(format!("{was}; now {now_placed}; version {}", summary.version));
        let status = self.commit(event)?;
        Ok((summary, was, status))
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

    /// Removes this machine's vault so a backup can be restored into a fresh one (R20). Needs the
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

    /// The head of the audit chain this vault file records (R29).
    pub fn audit_head(&self) -> &str {
        &self.doc.audit_head
    }

    /// What `vault status` shows about the open vault. Information only. `audit` is the chain
    /// as the daemon's checkpoint last checked it (`audit::check`), or what is wrong with it.
    pub fn status(&self, audit: Result<&audit::Checkpoint, String>) -> OpenedStatus {
        let doc = &self.doc;
        let mut by_kind = Vec::new();
        for kind in Kind::ALL {
            by_kind.push((kind, doc.records.iter().filter(|r| r.kind == kind).count()));
        }
        let (audit_lines, audit_files, audit_problem, recent_changes) = match audit {
            Ok(checkpoint) => {
                let recent = checkpoint
                    .recent_changes()
                    .map(|l| format!("{}  {} {}", l.t, l.event.event, l.event.name.clone().unwrap_or_default()))
                    .collect();
                (Some(checkpoint.lines()), Some(checkpoint.files()), None, recent)
            }
            Err(problem) => (None, None, Some(problem), Vec::new()),
        };
        OpenedStatus {
            vault_id: doc.vault_id.clone(),
            vault_identity: model::vault_identity(&doc.recovery_recipient),
            format: doc.format,
            created_at: doc.created_at.clone(),
            recovery_fingerprint: backup::fingerprint(&doc.recovery_recipient),
            kit_confirmed: doc.kit_confirmed,
            kit_path: doc.kit_path.clone(),
            mirror_dir: doc.mirror_dir.clone(),
            generation: doc.generation,
            secrets: doc.records.len(),
            by_kind,
            last_backup: doc.last_backup.clone(),
            intake_recipient: doc.intake_identity.as_ref().and_then(crate::intake::public_of).map(|(public, _)| public),
            audit_lines,
            audit_files,
            audit_problem,
            recent_changes,
        }
    }
}

/// How the audit log describes a stored secret: its kind and rule, or its kind and site.
fn describe(record: &Record) -> String {
    if let Some(info) = &record.wallet {
        return format!("wallet on {} at {}; caps {}", info.chain.label(), info.address, info.caps.describe(info.chain));
    }
    match &record.rule {
        Some(rule) => format!("{}; rule {}", record.kind.label(), rule.describe()),
        None => match (&record.fields, &record.app) {
            (Some(fields), _) => format!("{} for {}; fields {}", record.kind.label(), record.site, fields.join(", ")),
            (None, Some(app)) => format!(
                "{} for application {app:?}; {}",
                record.kind.label(),
                if record.may_lease() { "may be leased to builds" } else { "not leasable" }
            ),
            (None, None) => format!("{} for {}", record.kind.label(), record.site),
        },
    }
}

pub(crate) fn totp_code<'a>(doc: &'a VaultDoc, secret: &SecretRef) -> Result<(TotpCode, &'a Record), VaultError> {
    let record = doc.find_ref(secret).ok_or_else(|| secret.not_found())?;
    if record.kind != Kind::TwoFactor {
        return Err(VaultError::WrongKind);
    }
    Ok((totp::code_at(&record.value, record.totp.unwrap_or_default(), crate::now_unix())?, record))
}

/// Whether two record lists hold the same secrets: ids, versions, names, kinds, sites, rules and
/// values.
pub(crate) fn same_records(a: &[Record], b: &[Record]) -> bool {
    a.len() == b.len()
        && a.iter().all(|x| {
            b.iter().any(|y| {
                x.id == y.id
                    && x.version == y.version
                    && x.name == y.name
                    && x.kind == y.kind
                    && x.site == y.site
                    && x.rule == y.rule
                    && x.username == y.username
                    && x.totp == y.totp
                    && x.expires_at == y.expires_at
                    && x.handover == y.handover
                    && x.app == y.app
                    && x.leasable == y.leasable
                    && x.wallet == y.wallet
                    && x.value.same_as(&y.value)
            })
        })
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RestorePointInfo {
    mirror_dir: String,
    file: String,
}

/// Whether `vault reset` left a restore point on this machine.
pub fn has_restore_point(paths: &Paths) -> bool {
    paths.restore_point.is_file()
}

/// Restores a backup into an empty vault on this machine, with the recovery key (R20). The backup is
/// the file the person named, or the restore point `vault reset` kept. Makes a new vault key and
/// a new vault id; the restored vault starts its own line of backups. Keeps what is stable: the
/// recovery key (so the vault identity is the same) and every secret's id and version. A
/// format-1 backup's secrets get their ids here.
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
    let mut payload = backup::open_bytes(&data, &identity)?;
    if payload.recovery_recipient != backup::public_of(&identity) {
        return Err(VaultError::WrongRecoveryKey);
    }
    let from_format = payload.format;
    let migrated = model::migrate_records(&mut payload.records, store::new_random_id)?;
    let (check_secret, _) = backup::new_identity();
    let vault_id = store::new_vault_id()?;
    let key = SecretValue::random(32)?;
    keyprotect::store_new(&paths.dir, &key)?;
    let vault_identity = model::vault_identity(&payload.recovery_recipient);

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
        // Backups don't carry the intake key: a restored vault gets a new one, which the app
        // learns from `vault status --json` as it does for a new vault.
        intake_identity: Some(backup::new_identity().0),
        audit_head: audit::GENESIS.into(),
        generation: 1,
        last_backup: None,
        records: payload.records,
    };
    let mut event = AuditEvent::new("restore", "ok");
    event.detail = Some(format!(
        "new vault {vault_id} from {source} (vault {}, generation {}, format {from_format}{}), audit head then {}",
        payload.vault_id,
        payload.generation,
        if migrated > 0 { format!(", {migrated} secrets given ids") } else { String::new() },
        payload.audit_head
    ));
    doc.audit_head = audit_event(paths, event)?;
    store::save(paths, &key, &doc)?;
    let protection = keyprotect::protect(&paths.dir, &key);
    eprintln!("{} vault daemon: restored vault key: {protection}", crate::now_rfc3339());
    if from_restore_point {
        let _ = fs::remove_file(&paths.restore_point);
        let _ = fs::remove_file(&paths.restore_point_info);
    }
    let vault = Vault { paths: paths.clone(), key, doc };
    Ok((
        vault,
        RestoreReport {
            vault_id,
            vault_identity,
            from_vault_id: payload.vault_id,
            from_format,
            secrets,
            from_generation: payload.generation,
        },
    ))
}

impl Vault {
    /// The first backup of a vault the daemon just restored or opened.
    pub fn backup_if_needed(&mut self) -> Option<BackupStatus> {
        if self.needs_backup() { Some(self.backup_now()) } else { None }
    }
}
