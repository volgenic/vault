//! `vault status --json` and `vault install --json`: one JSON object for a program (the host
//! daemon) to read. Information only (R4): versions, paths, states, times and counts, never a
//! value, a secret's name or a recovery key. The audit log's recent changes, which name
//! secrets, are left out on purpose.
//!
//! The shapes are the types below (`StatusJson`, `InstallJson`), `schema` 1. `diagnose` is the
//! decision: plain values in, the `problems` list out, each with the exact command a person
//! would run. `gather_status` is the thin shell that reads the machine and asks the daemon.

use serde::Serialize;

use crate::error::VaultError;
use crate::keyprotect::{self, KeyState};
use crate::protocol::{PROTOCOL_VERSION, StatusReply};
use crate::store::{self, OwnerPaths, Paths};
use crate::{client, install};

/// The version of these JSON shapes. A field is only ever added within a schema; removing or
/// changing one makes a new schema number.
pub const SCHEMA: u32 = 1;

#[cfg(target_os = "macos")]
pub const PLATFORM: &str = "macos";
#[cfg(not(target_os = "macos"))]
pub const PLATFORM: &str = "linux";

/// One thing a person should do, and the exact command for it.
#[derive(Serialize, Clone, Debug)]
pub struct Problem {
    /// A stable code, e.g. `lingering_off`.
    pub code: &'static str,
    /// `error`: the vault isn't serving, or isn't safe. `warning`: it serves; something to do.
    pub severity: &'static str,
    /// One sentence for a person.
    pub sentence: String,
    /// The exact command a person would run, or null when there is none.
    pub how: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ErrorJson {
    pub code: &'static str,
    pub message: String,
}

impl From<&VaultError> for ErrorJson {
    fn from(error: &VaultError) -> Self {
        ErrorJson { code: error.code(), message: error.to_string() }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct ProgramJson {
    /// This build: the crate version and the commit it was built from.
    pub version: String,
    pub commit: String,
    /// The target it was built for, e.g. `x86_64-unknown-linux-musl`.
    pub target: String,
    /// The program that is running now.
    pub running_path: String,
    /// The installed program, `bin/vault` in the vault's base folder.
    pub installed: bool,
    pub installed_path: String,
    /// Whether the installed program is byte for byte this build (null when not installed).
    pub installed_is_this_build: Option<bool>,
}

#[derive(Serialize, Clone, Debug)]
pub struct DaemonJson {
    /// The daemon answered on its socket, as your own user (R22).
    pub running: bool,
    pub pid: Option<u32>,
    /// The daemon's build version (it can differ from the program's until it restarts).
    pub version: Option<String>,
    /// The vault-file format the daemon writes.
    pub format: Option<u32>,
    pub socket: String,
    /// The LaunchAgent's plist (macOS) or the systemd user unit (Linux).
    pub service_file: String,
    pub service_file_present: bool,
    pub log: String,
    /// Why it didn't answer, when it didn't.
    pub error: Option<ErrorJson>,
}

#[derive(Serialize, Clone, Debug)]
pub struct VaultJson {
    /// There is a vault here (from the daemon when it answers, else from the vault file on disk).
    pub initialized: bool,
    /// The vault's stable identity (survives restores); null unless the daemon answered.
    pub identity: Option<String>,
    /// This copy's id (new at every restore).
    pub vault_id: Option<String>,
    pub recovery_fingerprint: Option<String>,
    pub format: Option<u32>,
    pub created_at: Option<String>,
    /// Changes so far.
    pub generation: Option<u64>,
    /// How many secrets: a count, never names.
    pub secrets: Option<usize>,
    /// `vault reset` kept a restore point (`vault restore` restores it).
    pub restore_point: Option<bool>,
}

#[derive(Serialize, Clone, Debug)]
pub struct KeyJson {
    /// `tpm2` or `secure_enclave` (only when the running daemon unsealed its key from that file),
    /// `unchecked` (a sealed file is there, no running daemon says it opened it), `file` or `none`.
    pub kind: &'static str,
    /// For `file` and `unchecked`: why it isn't (known to be) sealed.
    pub reason: Option<String>,
    pub plain_copy_left: bool,
    /// For `file`: this machine could seal it now (`vault install` would).
    pub sealable: bool,
    /// The daemon is running on the plain key file although a sealed key is there.
    pub sealed_unusable: bool,
    pub detail: String,
}

impl From<KeyState> for KeyJson {
    fn from(state: KeyState) -> Self {
        KeyJson {
            kind: state.kind,
            reason: state.reason,
            plain_copy_left: state.plain_copy_left,
            sealable: state.sealable,
            sealed_unusable: state.sealed_unusable,
            detail: state.detail,
        }
    }
}

/// What protects this Mac's disk when it is off (#7689); null on Linux.
#[derive(Serialize, Clone, Debug)]
pub struct DiskJson {
    /// `fdesetup status`; null when it couldn't be read.
    pub filevault_on: Option<bool>,
    /// The account that logs in by itself at startup; null when none.
    pub auto_login_user: Option<String>,
}

/// How `vault status` rates what leaves the vault open to a stolen disk or a stolen Mac: an
/// unconfirmed Recovery Kit, FileVault off, automatic login (#7689). Warnings, not errors: an
/// error makes the host report the vault missing to agents, and the vault keeps working. They are
/// said loudly instead (`stolen_disk_banner`, in `vault install` and `vault status`).
const STOLEN_DISK_SEVERITY: &str = "warning";

/// The problems `stolen_disk_banner` shows.
pub const STOLEN_DISK_CODES: [&str; 3] = ["recovery_kit_pending", "filevault_off", "auto_login_on"];

/// The loud block `vault install` and `vault status` end with while a stolen disk or a stolen Mac
/// could still open the vault; empty when nothing does.
pub fn stolen_disk_banner(problems: &[Problem]) -> String {
    let found: Vec<&Problem> = problems.iter().filter(|p| STOLEN_DISK_CODES.contains(&p.code)).collect();
    if found.is_empty() {
        return String::new();
    }
    let mut text = format!(
        "\n!!! WARNING: a stolen disk or {} can open this vault until you deal with this:\n",
        crate::platform::MACHINE
    );
    for problem in found {
        text.push_str(&format!("!!!   - {}\n", problem.sentence));
        if let Some(how) = &problem.how {
            text.push_str(&format!("!!!     run: {how}\n"));
        }
    }
    text
}

#[derive(Serialize, Clone, Debug)]
pub struct KitJson {
    /// `pending` (not confirmed yet), `confirmed`, `none` (no vault) or `unknown` (the daemon
    /// didn't answer).
    pub state: &'static str,
    /// The kit file `vault install` wrote, while it is pending.
    pub path: Option<String>,
    pub file_present: Option<bool>,
}

#[derive(Serialize, Clone, Debug)]
pub struct BackupJson {
    /// The newest backup: `ok`, `failed`, `none` (none written yet) or `unknown` (the daemon
    /// didn't answer, or there is no vault).
    pub state: &'static str,
    pub generation: Option<u64>,
    pub at: Option<String>,
    pub file: Option<String>,
    pub detail: Option<String>,
    /// The local backups folder.
    pub folder: String,
}

/// Whether the vault comes back by itself after a restart.
#[derive(Serialize, Clone, Debug)]
pub struct BootJson {
    /// `systemd-user-service` (Linux) or `launch-agent` (macOS).
    pub mechanism: &'static str,
    /// Linux: it starts at boot with nobody logged in (systemd, lingering and the service
    /// enabled). macOS: the LaunchAgent is there and loaded, so it starts at each login.
    pub persistent: bool,
    /// Linux: this machine runs systemd. Null on macOS.
    pub systemd: Option<bool>,
    /// Linux: lingering is on for you. Null on macOS.
    pub lingering: Option<bool>,
    /// Linux: the user unit is enabled under `default.target`. Null on macOS.
    pub service_enabled: Option<bool>,
    /// macOS: the LaunchAgent is loaded. Null on Linux.
    pub launch_agent_loaded: Option<bool>,
}

#[derive(Serialize, Clone, Debug)]
pub struct AuditJson {
    pub intact: bool,
    pub lines: Option<usize>,
    /// How many files the chain runs through: `audit.log` and the rotated `audit.log.<n>`.
    pub files: Option<usize>,
    pub problem: Option<String>,
}

/// The vault's intake key (R40): Volgenic's app seals a value to it, so Volgenic's server can carry
/// the value to this vault without being able to read it.
#[derive(Serialize, Clone, Debug)]
pub struct IntakeJson {
    /// An age X25519 recipient, `age1...`.
    pub public_key: String,
    /// The first 12 hex digits of its SHA-256, as `abcd-ef01-2345` (the recovery key's form).
    pub fingerprint: String,
}

/// `vault status --json`.
#[derive(Serialize, Clone, Debug)]
pub struct StatusJson {
    pub schema: u32,
    /// No problem of severity `error`.
    pub healthy: bool,
    pub platform: &'static str,
    pub user: String,
    pub program: ProgramJson,
    /// The socket protocol this build speaks.
    pub protocol: u32,
    pub daemon: DaemonJson,
    pub vault: VaultJson,
    pub key_protection: KeyJson,
    /// macOS only: FileVault and automatic login.
    pub disk: Option<DiskJson>,
    pub recovery_kit: KitJson,
    pub backup: BackupJson,
    pub boot: BootJson,
    /// Null unless the daemon answered with a vault.
    pub audit: Option<AuditJson>,
    /// The intake key; null unless the daemon answered with a vault that has one.
    pub intake: Option<IntakeJson>,
    pub problems: Vec<Problem>,
}

/// A command for a person: the program quoted for a POSIX shell when it needs it.
pub fn shell_word(text: &str) -> String {
    let plain = !text.is_empty()
        && text.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '~' | ':' | '=' | '@' | '+'));
    if plain { text.to_string() } else { format!("'{}'", text.replace('\'', "'\\''")) }
}

fn command(program: &str, args: &str) -> String {
    format!("{} {args}", shell_word(program))
}

/// The problems in a status, most serious first. Pure: decides from the values only.
pub fn diagnose(status: &StatusJson, uid: u32) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut add = |code, severity, sentence: String, how: Option<String>| {
        problems.push(Problem { code, severity, sentence, how })
    };
    let program = &status.program;
    if !program.installed {
        add(
            "not_installed",
            "error",
            "The vault isn't installed for you on this machine.".into(),
            Some(command(&program.running_path, "install")),
        );
        return problems;
    }
    let vault_cmd = |args: &str| command(&program.installed_path, args);
    let install_cmd = vault_cmd("install");
    let linux = status.platform == "linux";
    let daemon = &status.daemon;

    if !daemon.running {
        let verified = daemon.error.as_ref().is_none_or(|e| e.code != "daemon_not_verified");
        if !verified {
            add(
                "daemon_not_verified",
                "error",
                format!(
                    "Something other than your own vault daemon is behind the socket {}, so nothing is sent to it.",
                    daemon.socket
                ),
                None,
            );
        } else {
            let how = if !daemon.service_file_present {
                install_cmd.clone()
            } else if linux && status.boot.systemd == Some(false) {
                vault_cmd("daemon")
            } else if linux {
                format!("systemctl --user restart {}", store::DAEMON_LABEL)
            } else if status.boot.launch_agent_loaded == Some(false) {
                install_cmd.clone()
            } else {
                format!("launchctl kickstart -k gui/{uid}/{}", store::DAEMON_LABEL)
            };
            add(
                "daemon_not_running",
                "error",
                format!("The vault's daemon isn't answering, so agents can't use secrets. Its log is {}.", daemon.log),
                Some(how),
            );
        }
    }

    if daemon.running && !status.vault.initialized {
        if status.vault.restore_point == Some(true) {
            add(
                "no_vault",
                "error",
                "There is no vault here; `vault reset` kept a restore point, which restores with the recovery key."
                    .into(),
                Some(vault_cmd("restore")),
            );
        } else {
            add(
                "no_vault",
                "error",
                "There is no vault here yet. Make a new one, or restore a backup with `vault restore FILE` and the recovery key."
                    .into(),
                Some(install_cmd.clone()),
            );
        }
    }

    if let (Some(daemon_version), Some(true)) = (&daemon.version, program.installed_is_this_build) {
        if daemon_version != &program.version {
            add(
                "daemon_outdated",
                "warning",
                format!(
                    "The daemon still runs version {daemon_version} although version {} is installed; it hasn't restarted since the update.",
                    program.version
                ),
                Some(install_cmd.clone()),
            );
        }
    }

    match status.backup.state {
        "failed" => add(
            "backup_failed",
            "error",
            format!(
                "The newest backup failed ({}), and the vault refuses changes until one succeeds.",
                status.backup.detail.clone().unwrap_or_default()
            ),
            Some(vault_cmd("backup")),
        ),
        "none" => add(
            "no_backup_yet",
            "warning",
            "No backup has been written yet.".into(),
            Some(vault_cmd("backup")),
        ),
        _ => {}
    }

    if let Some(audit) = &status.audit {
        if !audit.intact {
            add(
                "audit_chain_broken",
                "error",
                format!(
                    "The audit log's hash chain doesn't check out: {}.",
                    audit.problem.clone().unwrap_or_else(|| "unknown".into())
                ),
                Some(vault_cmd("audit --all")),
            );
        }
    }

    if status.recovery_kit.state == "pending" {
        // The kit opens every backup on any machine, sealed key or not, so until it is confirmed
        // and gone, a copy of this disk (or a backup of it, or the backups' mirror) opens the vault.
        let sentence = match &status.recovery_kit.path {
            Some(path) => format!(
                "The Recovery Kit ({path}) isn't confirmed yet. It opens every backup of this vault on any machine, so until it is confirmed and its file deleted, a copy of this disk or of its backups opens your secrets, and sealing the key to this {} doesn't protect them: keep a copy off this machine, then confirm it, which deletes the file.",
                crate::platform::MACHINE
            ),
            None => format!(
                "The Recovery Kit isn't confirmed yet. It opens every backup of this vault on any machine, so until it is confirmed, sealing the key to this {} doesn't protect the backups: keep a copy off this machine, then confirm it.",
                crate::platform::MACHINE
            ),
        };
        add("recovery_kit_pending", STOLEN_DISK_SEVERITY, sentence, Some(vault_cmd("confirm-kit")));
    }

    if let Some(disk) = &status.disk {
        let disk = crate::platform::DiskProtection { filevault_on: disk.filevault_on, auto_login_user: disk.auto_login_user.clone() };
        for (code, sentence) in crate::platform::disk_protection_problems(&disk) {
            add(code, STOLEN_DISK_SEVERITY, sentence, None);
        }
    }

    let key = &status.key_protection;
    if key.sealed_unusable {
        add(
            "key_sealed_unusable",
            "error",
            format!(
                "The vault key sealed to this {} didn't open the vault, so the daemon is running on the plain key file; its log says why.",
                crate::platform::MACHINE
            ),
            Some(install_cmd.clone()),
        );
    } else if key.plain_copy_left {
        add(
            "key_plain_copy_left",
            "warning",
            format!(
                "The vault key is sealed to this {}, but a plain key file is still on disk, and in any backup made while it was there: `vault install` replaces the key and removes it.",
                crate::platform::MACHINE
            ),
            Some(install_cmd.clone()),
        );
    } else if key.kind == "file" && key.sealable {
        add(
            "key_not_sealed",
            "warning",
            if !linux {
                "The vault key is a plain file although this Mac's Secure Enclave could wrap it.".into()
            } else {
                "The vault key is a plain file although this machine's TPM could seal it.".into()
            },
            Some(install_cmd.clone()),
        );
    }

    let boot = &status.boot;
    if linux {
        if boot.systemd == Some(false) {
            add(
                "no_systemd",
                "warning",
                "This machine isn't running systemd, so nothing starts the vault after a reboot; it runs only while started by hand."
                    .into(),
                Some(vault_cmd("daemon")),
            );
        } else {
            if boot.lingering == Some(false) {
                add(
                    "lingering_off",
                    "warning",
                    format!(
                        "Lingering is off for {}, so the vault runs only while you're logged in, and not after a reboot.",
                        status.user
                    ),
                    Some(format!("sudo loginctl enable-linger {}", shell_word(&status.user))),
                );
            }
            if boot.service_enabled == Some(false) {
                add(
                    "service_not_enabled",
                    "warning",
                    "The vault's systemd user service isn't enabled, so it doesn't start at boot.".into(),
                    Some(install_cmd.clone()),
                );
            }
        }
    } else if daemon.running && boot.launch_agent_loaded == Some(false) {
        add(
            "launch_agent_not_loaded",
            "warning",
            "The vault's LaunchAgent isn't loaded, so it won't start at your next login.".into(),
            Some(install_cmd.clone()),
        );
    }

    // Errors first, keeping the order above within each severity.
    problems.sort_by_key(|p| p.severity != "error");
    problems
}

fn same_file_bytes(a: &std::path::Path, b: &std::path::Path) -> Option<bool> {
    if a == b {
        return Some(true);
    }
    let (Ok(x), Ok(y)) = (crate::platform::sha256_of(a), crate::platform::sha256_of(b)) else {
        return None;
    };
    Some(x == y)
}

/// Reads this machine's vault state and asks the daemon (when it answers): `vault status --json`.
pub fn gather_status(paths: &Paths) -> StatusJson {
    let uid = unsafe { libc::getuid() };
    let owner = OwnerPaths::for_uid(uid).ok();
    let user = owner.as_ref().map_or(uid.to_string(), |o| o.name.clone());
    let running = std::env::current_exe().ok().and_then(|p| p.canonicalize().ok());
    let installed = paths.program.is_file();
    let program = ProgramJson {
        version: crate::VERSION.into(),
        commit: crate::GIT_COMMIT.into(),
        target: crate::TARGET.into(),
        running_path: running.as_ref().map_or_else(String::new, |p| p.display().to_string()),
        installed,
        installed_path: paths.program.display().to_string(),
        installed_is_this_build: match (&running, installed) {
            (Some(running), true) => same_file_bytes(running, &paths.program),
            _ => None,
        },
    };

    let reply: Result<StatusReply, VaultError> =
        if installed { client::status(paths) } else { Err(VaultError::NotInstalled) };
    let daemon = DaemonJson {
        running: reply.is_ok(),
        pid: reply.as_ref().ok().map(|r| r.pid),
        version: reply.as_ref().ok().map(|r| r.version.clone()),
        format: reply.as_ref().ok().map(|r| r.format),
        socket: paths.socket.display().to_string(),
        service_file: paths.service_file.display().to_string(),
        service_file_present: std::fs::symlink_metadata(&paths.service_file).is_ok(),
        log: paths.daemon_log.display().to_string(),
        error: reply.as_ref().err().map(ErrorJson::from),
    };

    let opened = reply.as_ref().ok().and_then(|r| r.vault.as_ref());
    let vault = VaultJson {
        initialized: match &reply {
            Ok(r) => r.vault.is_some(),
            Err(_) => store::vault_exists(paths),
        },
        identity: opened.map(|v| v.vault_identity.clone()),
        vault_id: opened.map(|v| v.vault_id.clone()),
        recovery_fingerprint: opened.map(|v| v.recovery_fingerprint.clone()),
        format: opened.map(|v| v.format),
        created_at: opened.map(|v| v.created_at.clone()),
        generation: opened.map(|v| v.generation),
        secrets: opened.map(|v| v.secrets),
        restore_point: reply.as_ref().ok().map(|r| r.restore_point),
    };

    let recovery_kit = match (&reply, opened) {
        (Ok(_), Some(v)) if v.kit_confirmed => KitJson { state: "confirmed", path: None, file_present: None },
        (Ok(_), Some(v)) => KitJson {
            state: "pending",
            path: v.kit_path.clone(),
            file_present: v.kit_path.as_ref().map(|p| std::fs::symlink_metadata(p).is_ok()),
        },
        (Ok(_), None) => KitJson { state: "none", path: None, file_present: None },
        (Err(_), _) => {
            let kit = owner.as_ref().map(|o| o.default_kit.clone());
            KitJson {
                state: "unknown",
                path: kit.as_ref().map(|p| p.display().to_string()),
                file_present: kit.as_ref().map(|p| std::fs::symlink_metadata(p).is_ok()),
            }
        }
    };

    let folder = paths.local_backups.display().to_string();
    let backup = match opened.map(|v| v.last_backup.as_ref()) {
        Some(Some(b)) => BackupJson {
            state: if b.ok { "ok" } else { "failed" },
            generation: Some(b.generation),
            at: Some(b.at.clone()),
            file: (!b.file.is_empty()).then(|| b.file.clone()),
            detail: Some(b.detail.clone()),
            folder,
        },
        Some(None) => BackupJson { state: "none", generation: None, at: None, file: None, detail: None, folder },
        None => BackupJson { state: "unknown", generation: None, at: None, file: None, detail: None, folder },
    };

    let audit = opened.map(|v| AuditJson {
        intact: v.audit_lines.is_some() && v.audit_problem.is_none(),
        lines: v.audit_lines,
        files: v.audit_files,
        problem: v.audit_problem.clone(),
    });

    let intake = opened.and_then(|v| v.intake_recipient.as_ref()).map(|public| IntakeJson {
        public_key: public.clone(),
        fingerprint: crate::backup::fingerprint(public),
    });

    let mut status = StatusJson {
        schema: SCHEMA,
        healthy: true,
        platform: PLATFORM,
        user,
        program,
        protocol: PROTOCOL_VERSION,
        daemon,
        vault,
        key_protection: keyprotect::state(&paths.dir, reply.as_ref().ok().and_then(|r| r.key_source.as_deref())).into(),
        disk: cfg!(target_os = "macos").then(|| {
            let disk = crate::platform::disk_protection();
            DiskJson { filevault_on: disk.filevault_on, auto_login_user: disk.auto_login_user }
        }),
        recovery_kit,
        backup,
        boot: install::boot_state(paths, uid, owner.as_ref().map(|o| o.name.as_str())),
        audit,
        intake,
        problems: Vec::new(),
    };
    status.problems = diagnose(&status, uid);
    status.healthy = !status.problems.iter().any(|p| p.severity == "error");
    status
}

/// What `vault install --json` did with the program.
#[derive(Serialize, Clone, Debug)]
pub struct InstallProgramJson {
    /// `installed` (there was none), `updated` (different bytes), `reinstalled` (the same
    /// bytes again) or `in_place` (it ran from the installed path).
    pub action: &'static str,
    pub path: String,
    pub from: String,
    pub version: String,
    pub commit: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct InstallVaultJson {
    /// `made` (a new vault), `kept` (the existing one) or `none` (none made: `--for-restore`,
    /// or a key without a vault file is there).
    pub action: &'static str,
    /// For `made`, from the install; for `kept`, from the daemon after it (null if it didn't
    /// answer).
    pub identity: Option<String>,
    pub vault_id: Option<String>,
    pub recovery_fingerprint: Option<String>,
    /// The Recovery Kit written for a new vault (mode 0600; it holds the recovery key, which
    /// never appears here).
    pub kit_written: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct InstallServiceJson {
    pub file: String,
    /// The daemon was started and answered.
    pub started: bool,
    /// Why it wasn't started (e.g. no systemd), when it wasn't.
    pub not_started_reason: Option<String>,
    /// Linux: lingering is on after the install (null on macOS or without systemd).
    pub lingering: Option<bool>,
    pub pid: Option<u32>,
}

/// `vault install --json`.
#[derive(Serialize, Clone, Debug)]
pub struct InstallJson {
    pub schema: u32,
    /// The install finished without an error.
    pub ok: bool,
    pub error: Option<ErrorJson>,
    pub platform: &'static str,
    pub for_restore: bool,
    pub program: Option<InstallProgramJson>,
    pub vault: Option<InstallVaultJson>,
    /// What sealing (or not) did, in a sentence, when the install touched the key.
    pub key_note: Option<String>,
    pub service: Option<InstallServiceJson>,
    /// `status.problems`, here too for convenience.
    pub problems: Vec<Problem>,
    /// `vault status --json`, read right after the install.
    pub status: Option<StatusJson>,
}

impl InstallJson {
    pub fn new(for_restore: bool) -> InstallJson {
        InstallJson {
            schema: SCHEMA,
            ok: false,
            error: None,
            platform: PLATFORM,
            for_restore,
            program: None,
            vault: None,
            key_note: None,
            service: None,
            problems: Vec::new(),
            status: None,
        }
    }
}
