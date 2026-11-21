//! Installing the vault: `vault install`, run as the owner, no sudo. It copies the program into
//! the vault's base folder (`bin/vault`), makes the vault (if there is none yet) with its key
//! and Recovery Kit, and starts the daemon. Running it again with a new build updates the
//! program and restarts the daemon, and keeps the vault.
//!
//! - **macOS:** the daemon is a LaunchAgent in the owner's login, `com.volgenic.vault`.
//!   `vault install-mirror` adds the optional backup mirror (macOS only for now).
//! - **Linux:** the daemon is a systemd *user* service, `volgenic-vault.service`, with
//!   lingering turned on for the owner (`loginctl enable-linger`), so systemd starts it at boot
//!   with nobody logged in, and restarts it whenever it stops (`Restart=always`). A user unit
//!   rather than a system unit under a dedicated account because it needs no root: the
//!   program, the files and the daemon stay the owner's, exactly as on a Mac, so the same
//!   threat model and caller check apply, and `vault install` updates it without sudo. A
//!   dedicated account is the separate-user design the owner retired in pull request #4.
//!
//! On both, the vault key is sealed to the machine (`keyprotect::protect`): to the Secure Enclave
//! on a Mac that has one, to the TPM on Linux when there is one. Running `vault install` again
//! seals a key that is still a plain file.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::client;
use crate::error::VaultError;
use crate::keyprotect;
use crate::report::{self, BootJson, ErrorJson, InstallJson, InstallProgramJson, InstallServiceJson, InstallVaultJson};
use crate::store::{self, OwnerPaths, Paths};
use crate::vault;

#[cfg(target_os = "macos")]
use self::launchd as service;
#[cfg(not(target_os = "macos"))]
use self::systemd as service;

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn ask(prompt: &str) -> Result<String, VaultError> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn run(program: &str, args: &[&str]) -> Result<String, VaultError> {
    run_with(program, args, &[])
}

/// Runs a program at its fixed path (never through `$PATH`) and returns what it printed.
fn run_with(program: &str, args: &[&str], env: &[(&str, &str)]) -> Result<String, VaultError> {
    // No input: a polkit agent (which `loginctl` starts only on a terminal) can never prompt (R33).
    let out = Command::new(program)
        .args(args)
        .envs(env.iter().copied())
        .stdin(std::process::Stdio::null())
        .output()?;
    if !out.status.success() {
        return Err(VaultError::Io(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn ensure_dir(dir: &Path) -> Result<(), VaultError> {
    if !dir.is_dir() {
        fs::create_dir_all(dir)?;
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Copies this build to the program path, through a temporary file and a rename, and says what
/// that was: `installed`, `updated`, `reinstalled` (the same bytes) or `in_place`.
fn install_program(paths: &Paths, exe: &Path) -> Result<&'static str, VaultError> {
    if exe == paths.program {
        return Ok("in_place");
    }
    let action = match fs::read(&paths.program) {
        Err(_) => "installed",
        Ok(old) => {
            if fs::read(exe).is_ok_and(|new| new == old) { "reinstalled" } else { "updated" }
        }
    };
    let temp = paths.bin_dir.join(".vault.new");
    let _ = fs::remove_file(&temp);
    let bytes = fs::read(exe)?;
    {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o700).open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temp, &paths.program)?;
    Ok(action)
}

/// Prints a line of the install's prose, unless the result is to be JSON.
macro_rules! say {
    ($json:expr, $($arg:tt)*) => {
        if !$json {
            println!($($arg)*);
        }
    };
}

/// `vault install`: as the owner, no sudo, no questions, no terminal needed. With `json`, prints
/// one JSON object (`report::InstallJson`) instead of prose, errors included.
pub fn install(for_restore: bool, json: bool) -> Result<(), VaultError> {
    let mut out = InstallJson::new(for_restore);
    let result = install_steps(for_restore, json, &mut out);
    if json {
        out.ok = result.is_ok();
        out.error = result.as_ref().err().map(ErrorJson::from);
        if out.program.is_some() {
            let status = report::gather_status(&Paths::current());
            if let Some(vault) = out.vault.as_mut().filter(|v| v.action == "kept") {
                vault.identity = status.vault.identity.clone();
                vault.vault_id = status.vault.vault_id.clone();
                vault.recovery_fingerprint = status.vault.recovery_fingerprint.clone();
            }
            out.problems = status.problems.clone();
            out.status = Some(status);
        }
        let text = serde_json::to_string_pretty(&out).map_err(|_| VaultError::Io("JSON encoding".into()))?;
        println!("{text}");
    } else if result.is_ok() {
        // The Recovery Kit, FileVault and automatic login, loudly (#7689).
        print!("{}", report::stolen_disk_banner(&report::gather_status(&Paths::current()).problems));
    }
    result
}

fn install_steps(for_restore: bool, json: bool, out: &mut InstallJson) -> Result<(), VaultError> {
    let uid = unsafe { libc::getuid() };
    if uid == 0 || unsafe { libc::geteuid() } == 0 {
        return Err(VaultError::Io("run `vault install` as yourself, without sudo".into()));
    }
    let paths = Paths::current();
    let owner = OwnerPaths::for_uid(uid)?;
    for dir in [&paths.base, &paths.bin_dir, &paths.dir, &paths.local_backups, &paths.log_dir] {
        ensure_dir(dir)?;
    }
    // `vault/` (the vault file, its key, the audit log) stays out of Time Machine (#7689): it can't
    // be opened on another Mac anyway, and a plain key file (a Mac with no Secure Enclave) would
    // otherwise go into every backup. The vault's own backups (`vault-backups/`, its mirror) are
    // what a restore uses, with the recovery key, and stay in.
    if let Err(why) = crate::platform::exclude_from_backups(&paths.dir) {
        say!(json, "warning:  {} couldn't be kept out of Time Machine: {why}", paths.dir.display());
    }
    // On Linux the socket's folder under /run/user is systemd's to make (RuntimeDirectory).
    if paths.socket_dir.starts_with(&paths.base) {
        ensure_dir(&paths.socket_dir)?;
    }
    if let Some(dir) = paths.service_file.parent() {
        fs::create_dir_all(dir)?;
    }

    // Stop a running daemon before replacing the program.
    service::stop(uid);
    let exe = std::env::current_exe()?.canonicalize()?;
    let action = install_program(&paths, &exe)?;
    out.program = Some(InstallProgramJson {
        action,
        path: paths.program.display().to_string(),
        from: exe.display().to_string(),
        version: crate::VERSION.into(),
        commit: crate::GIT_COMMIT.into(),
    });
    say!(json, "program:  {}", paths.program.display());

    if store::vault_exists(&paths) {
        say!(json, "vault:    kept");
        out.vault = Some(InstallVaultJson {
            action: "kept",
            identity: None,
            vault_id: None,
            recovery_fingerprint: None,
            kit_written: None,
        });
        let note = vault::reseal(&paths);
        say!(json, "key:      {note}");
        out.key_note = Some(note);
    } else if for_restore || keyprotect::key_exists(&paths.dir) {
        say!(json, "vault:    none (restore one with `vault restore FILE`)");
        out.vault = Some(InstallVaultJson {
            action: "none",
            identity: None,
            vault_id: None,
            recovery_fingerprint: None,
            kit_written: None,
        });
    } else {
        let report = vault::init(&paths, &owner.default_kit, &owner.default_mirror_dir())?;
        say!(json, "vault:    {} made (identity {})", report.vault_id, report.vault_identity);
        say!(json, "key:      {}", report.key_protection);
        say!(
            json,
            "kit:      {} (holds the recovery key for backups; stash it when you like)",
            report.kit_path.display()
        );
        out.vault = Some(InstallVaultJson {
            action: "made",
            identity: Some(report.vault_identity.clone()),
            vault_id: Some(report.vault_id.clone()),
            recovery_fingerprint: Some(report.recovery_fingerprint.clone()),
            kit_written: Some(report.kit_path.display().to_string()),
        });
        out.key_note = Some(report.key_protection.clone());
    }

    let mut service_out = InstallServiceJson {
        file: paths.service_file.display().to_string(),
        started: false,
        not_started_reason: None,
        lingering: None,
        pid: None,
    };
    let started = service::start(&paths, &owner, json, &mut service_out);
    let started = match started {
        Ok(started) => started,
        Err(error) => {
            out.service = Some(service_out);
            return Err(error);
        }
    };
    if let Started::No(why) = started {
        say!(json, "daemon:   not started: {why}");
        say!(json, "          start it yourself: {} daemon", paths.program.display());
        service_out.not_started_reason = Some(why);
        out.service = Some(service_out);
        return Ok(());
    }
    if client::wait_for_daemon(&paths, Duration::from_secs(30)) {
        let status = client::status(&paths)?;
        say!(json, "daemon:   running (pid {}), socket {}", status.pid, paths.socket.display());
        service_out.started = true;
        service_out.pid = Some(status.pid);
        out.service = Some(service_out);
        Ok(())
    } else {
        out.service = Some(service_out);
        Err(VaultError::Daemon(format!("the daemon didn't answer within 30s; its log is {}", paths.daemon_log.display())))
    }
}

/// Whether the vault comes back by itself after a restart, for `vault status --json`.
pub fn boot_state(paths: &Paths, uid: u32, user: Option<&str>) -> BootJson {
    service::boot_state(paths, uid, user)
}

/// Whether `service::start` started the daemon.
enum Started {
    Yes,
    /// Not started, and why (the service manager isn't there). Linux only.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    No(String),
}

/// The LaunchAgent in the owner's login (macOS).
#[cfg(target_os = "macos")]
mod launchd {
    use std::process::Command;

    use super::{Started, run};
    use crate::error::VaultError;
    use crate::report::{BootJson, InstallServiceJson};
    use crate::store::{self, OwnerPaths, Paths};

    pub fn stop(uid: u32) {
        let domain = format!("gui/{uid}");
        let _ = Command::new("/bin/launchctl").args(["bootout", &format!("{domain}/{}", store::DAEMON_LABEL)]).output();
    }

    pub fn start(
        paths: &Paths,
        owner: &OwnerPaths,
        _json: bool,
        _out: &mut InstallServiceJson,
    ) -> Result<Started, VaultError> {
        let domain = format!("gui/{}", owner.uid);
        store::write_atomic_mode(&paths.service_file, daemon_plist(paths).as_bytes(), 0o644)?;
        run("/bin/launchctl", &["bootstrap", &domain, &paths.service_file.display().to_string()])?;
        Ok(Started::Yes)
    }

    /// The LaunchAgent is there and loaded in your login (`launchctl print`), so it starts at
    /// each login and launchd keeps it running.
    pub fn boot_state(paths: &Paths, uid: u32, _user: Option<&str>) -> BootJson {
        let present = paths.service_file.is_file();
        let loaded = Command::new("/bin/launchctl")
            .args(["print", &format!("gui/{uid}/{}", store::DAEMON_LABEL)])
            .stdin(std::process::Stdio::null())
            .output()
            .is_ok_and(|out| out.status.success());
        BootJson {
            mechanism: "launch-agent",
            persistent: present && loaded,
            systemd: None,
            lingering: None,
            service_enabled: None,
            launch_agent_loaded: Some(loaded),
        }
    }

    pub fn xml_escape(text: &str) -> String {
        text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    }

    fn daemon_plist(paths: &Paths) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array><string>{program}</string><string>daemon</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
            label = store::DAEMON_LABEL,
            program = xml_escape(&paths.program.display().to_string()),
            log = xml_escape(&paths.daemon_log.display().to_string()),
        )
    }
}

/// The systemd user service, started at boot by lingering (Linux).
#[cfg(not(target_os = "macos"))]
mod systemd {
    use std::process::Command;

    use super::{Started, run_with};
    use crate::error::VaultError;
    use crate::platform;
    use crate::report::{BootJson, InstallServiceJson};
    use crate::store::{self, OwnerPaths, Paths};

    const SYSTEMCTL: &str = "/usr/bin/systemctl";
    const LOGINCTL: &str = "/usr/bin/loginctl";

    /// `systemctl --user` finds the user's service manager through `$XDG_RUNTIME_DIR`; a shell
    /// from `su` or `sudo -u` may not have it set.
    fn user_env(uid: u32) -> Vec<(String, String)> {
        match std::env::var_os("XDG_RUNTIME_DIR") {
            Some(_) => Vec::new(),
            None => vec![("XDG_RUNTIME_DIR".into(), format!("/run/user/{uid}"))],
        }
    }

    pub fn stop(uid: u32) {
        if platform::systemd_booted() {
            let _ = Command::new(SYSTEMCTL)
                .args(["--user", "stop", store::DAEMON_LABEL])
                .envs(user_env(uid))
                .stdin(std::process::Stdio::null())
                .output();
        }
    }

    /// A value for a unit file: `%` doubled (systemd's specifiers), and for `ExecStart` the
    /// program in double quotes with `"` and `\` escaped.
    fn escape(text: &str) -> String {
        text.replace('%', "%%")
    }

    fn quoted(text: &str) -> String {
        format!("\"{}\"", escape(text).replace('\\', "\\\\").replace('"', "\\\""))
    }

    pub fn unit(paths: &Paths) -> String {
        format!(
            "# Written by `vault install`; running it again rewrites this file.\n\
             [Unit]\n\
             Description=Volgenic vault: agents use your secrets without seeing them\n\
             Documentation=https://github.com/volgenic/vault\n\
             # Never give up restarting it.\n\
             StartLimitIntervalSec=0\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={program} daemon\n\
             Restart=always\n\
             RestartSec=2\n\
             # The socket's folder: $XDG_RUNTIME_DIR/volgenic, that is /run/user/<uid>/volgenic, 0700.\n\
             RuntimeDirectory=volgenic\n\
             RuntimeDirectoryMode=0700\n\
             UMask=0077\n\
             LimitCORE=0\n\
             NoNewPrivileges=yes\n\
             UnsetEnvironment=SSL_CERT_FILE SSL_CERT_DIR\n\
             StandardOutput=append:{log}\n\
             StandardError=append:{log}\n\
             \n\
             [Install]\n\
             # With lingering on, the user's service manager starts at boot, and this with it.\n\
             WantedBy=default.target\n",
            program = quoted(&paths.program.display().to_string()),
            log = escape(&paths.daemon_log.display().to_string()),
        )
    }

    pub fn start(
        paths: &Paths,
        owner: &OwnerPaths,
        json: bool,
        out: &mut InstallServiceJson,
    ) -> Result<Started, VaultError> {
        store::write_atomic_mode(&paths.service_file, unit(paths).as_bytes(), 0o644)?;
        say!(json, "service:  {}", paths.service_file.display());
        if !platform::systemd_booted() {
            return Ok(Started::No("this machine isn't running systemd".into()));
        }
        // Lingering first: it starts the user's service manager now and at every boot, with
        // nobody logged in. Turning it on for yourself needs no root on most distributions
        // (polkit's `set-self-linger`); where it does, say how. `--no-ask-password`: never a
        // polkit prompt, with or without a terminal (R33).
        let lingering = run_with(LOGINCTL, &["--no-ask-password", "enable-linger", &owner.name], &[]).is_ok()
            || linger_is_on(&owner.name);
        out.lingering = Some(lingering);
        if lingering {
            say!(json, "boot:     starts at boot with nobody logged in (lingering is on for {})", owner.name);
        } else {
            say!(json, "boot:     lingering couldn't be turned on, so the vault runs only while you're logged in.");
            say!(json, "          To serve after a reboot with nobody logged in, run once:");
            say!(json, "            sudo loginctl enable-linger {}", owner.name);
        }
        let env = user_env(owner.uid);
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        run_with(SYSTEMCTL, &["--user", "--no-ask-password", "daemon-reload"], &env)?;
        run_with(SYSTEMCTL, &["--user", "--no-ask-password", "enable", store::DAEMON_LABEL], &env)?;
        run_with(SYSTEMCTL, &["--user", "--no-ask-password", "restart", store::DAEMON_LABEL], &env)?;
        Ok(Started::Yes)
    }

    /// Lingering is systemd-logind's flag file `/var/lib/systemd/linger/<user>`; the unit is
    /// enabled when its link is in `default.target.wants`. Files only: nothing is started.
    pub fn boot_state(paths: &Paths, _uid: u32, user: Option<&str>) -> BootJson {
        let systemd = platform::systemd_booted();
        let lingering = user.map(|name| std::path::Path::new("/var/lib/systemd/linger").join(name).exists());
        let enabled = paths.service_file.parent().map(|dir| {
            std::fs::symlink_metadata(dir.join("default.target.wants").join(store::DAEMON_LABEL)).is_ok()
        });
        BootJson {
            mechanism: "systemd-user-service",
            persistent: systemd && lingering == Some(true) && enabled == Some(true),
            systemd: Some(systemd),
            lingering,
            service_enabled: enabled,
            launch_agent_loaded: None,
        }
    }

    fn linger_is_on(name: &str) -> bool {
        run_with(LOGINCTL, &["--no-ask-password", "show-user", name, "--property=Linger", "--value"], &[])
            .is_ok_and(|out| out.trim() == "yes")
    }
}

#[cfg(target_os = "macos")]
fn mirror_plist(paths: &Paths, owner: &OwnerPaths) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array><string>{program}</string><string>mirror</string></array>
  <key>WatchPaths</key>
  <array><string>{watch}</string></array>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
        label = store::MIRROR_LABEL,
        program = launchd::xml_escape(&paths.program.display().to_string()),
        watch = launchd::xml_escape(&paths.local_backups.display().to_string()),
        log = launchd::xml_escape(&owner.mirror_log.display().to_string()),
    )
}

/// `vault install-mirror` on Linux: not yet (the mirror is a LaunchAgent).
#[cfg(not(target_os = "macos"))]
pub fn install_mirror(_yes: bool) -> Result<(), VaultError> {
    Err(VaultError::UnsupportedPlatform("the backup mirror (`vault install-mirror`)".into()))
}

/// `vault install-mirror`: the owner's LaunchAgent that copies backups to the mirror folder.
#[cfg(target_os = "macos")]
pub fn install_mirror(yes: bool) -> Result<(), VaultError> {
    let uid = unsafe { libc::getuid() };
    if uid == 0 || unsafe { libc::geteuid() } == 0 {
        return Err(VaultError::Io("run `vault install-mirror` as yourself, without sudo".into()));
    }
    let paths = Paths::current();
    if !paths.program.is_file() {
        return Err(VaultError::NotInstalled);
    }
    let owner = OwnerPaths::for_uid(uid)?;
    let plan = client::mirror_plan(&paths)?;
    println!("The mirror is a small agent in your login, {}. It copies each new", store::MIRROR_LABEL);
    println!("backup from {}", plan.local_dir);
    println!("to {}", plan.mirror_dir);
    println!("and checks every copy byte for byte. It holds no key and can't decrypt anything.");
    println!();
    println!("What macOS may show:");
    println!("  - A notification, \"Background Items Added\": nothing to click.");
    println!("  - Once, if that folder is in iCloud Drive (or Desktop, Documents, Downloads or an");
    println!("    external disk): a dialog asking whether \"vault\" may access files there. Click Allow.");
    println!("    macOS remembers it for this program's path and signature, which updates keep.");
    println!("No other dialog can come from the vault.");
    if !yes {
        ask("Press Return to continue. ")?;
    }
    let started = crate::now_rfc3339();
    if let Some(dir) = owner.mirror_plist.parent() {
        fs::create_dir_all(dir)?;
    }
    if let Some(dir) = owner.mirror_log.parent() {
        fs::create_dir_all(dir)?;
    }
    store::write_atomic_mode(&owner.mirror_plist, mirror_plist(&paths, &owner).as_bytes(), 0o644)?;
    let domain = format!("gui/{uid}");
    let _ = Command::new("/bin/launchctl").args(["bootout", &format!("{domain}/{}", store::MIRROR_LABEL)]).output();
    run("/bin/launchctl", &["bootstrap", &domain, &owner.mirror_plist.display().to_string()])?;
    println!("Mirror installed: {}", owner.mirror_plist.display());
    println!("Waiting for its first copy (if macOS asks about file access for \"vault\", click Allow)...");
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    while std::time::Instant::now() < deadline {
        if let Ok(status) = client::status(&paths) {
            if let Some(mirror) = status.mirror.filter(|m| m.at >= started) {
                if mirror.ok {
                    println!(
                        "  mirror:        OK: copied {}, already there {}, newest generation {}",
                        mirror.copied,
                        mirror.already_there,
                        mirror.newest_generation.map_or("none".into(), |g| g.to_string())
                    );
                    return Ok(());
                }
                println!("  mirror:        FAILED: {}", mirror.detail);
                println!("  its log: {}", owner.mirror_log.display());
                return Err(VaultError::BackupFailed(mirror.detail));
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(VaultError::BackupFailed(format!(
        "the mirror didn't report within 5 minutes; its log is {}",
        owner.mirror_log.display()
    )))
}
