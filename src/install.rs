//! Installing the vault: `vault install`, run as the owner, no sudo. It copies the program to
//! `~/Library/Application Support/Volgenic/bin/vault`, makes the vault (if there is none yet)
//! with its key file and Recovery Kit, and starts the daemon as a LaunchAgent in the owner's
//! login. Running it again with a new build updates the program and restarts the daemon, and
//! keeps the vault. `vault install-mirror` adds the optional backup mirror.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::client;
use crate::error::VaultError;
use crate::keyprotect;
use crate::store::{self, OwnerPaths, Paths};
use crate::vault;

fn ask(prompt: &str) -> Result<String, VaultError> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn run(program: &str, args: &[&str]) -> Result<String, VaultError> {
    let out = Command::new(program).args(args).output()?;
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

/// Copies this build to the program path, through a temporary file and a rename.
fn install_program(paths: &Paths, exe: &Path) -> Result<(), VaultError> {
    if exe == paths.program {
        return Ok(());
    }
    let temp = paths.bin_dir.join(".vault.new");
    let _ = fs::remove_file(&temp);
    let bytes = fs::read(exe)?;
    {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o700).open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temp, &paths.program)?;
    Ok(())
}

fn xml_escape(text: &str) -> String {
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

/// `vault install`: as the owner, no sudo, no questions.
pub fn install(for_restore: bool) -> Result<(), VaultError> {
    let uid = unsafe { libc::getuid() };
    if uid == 0 || unsafe { libc::geteuid() } == 0 {
        return Err(VaultError::Io("run `vault install` as yourself, without sudo".into()));
    }
    let paths = Paths::current();
    let owner = OwnerPaths::for_uid(uid)?;
    for dir in [&paths.base, &paths.bin_dir, &paths.dir, &paths.local_backups, &paths.socket_dir, &paths.log_dir] {
        ensure_dir(dir)?;
    }
    if let Some(dir) = paths.daemon_plist.parent() {
        fs::create_dir_all(dir)?;
    }

    // Stop a running daemon before replacing the program.
    let domain = format!("gui/{uid}");
    let _ = Command::new("/bin/launchctl").args(["bootout", &format!("{domain}/{}", store::DAEMON_LABEL)]).output();
    let exe = std::env::current_exe()?.canonicalize()?;
    install_program(&paths, &exe)?;
    println!("program:  {}", paths.program.display());

    if store::vault_exists(&paths) {
        println!("vault:    kept");
    } else if for_restore || keyprotect::key_exists(&paths.dir) {
        println!("vault:    none (restore one with `vault restore FILE`)");
    } else {
        let report = vault::init(&paths, &owner.default_kit, &owner.icloud_backups())?;
        println!("vault:    {} made", report.vault_id);
        println!("kit:      {} (holds the recovery key for backups; stash it when you like)", report.kit_path.display());
    }

    store::write_atomic_mode(&paths.daemon_plist, daemon_plist(&paths).as_bytes(), 0o644)?;
    run("/bin/launchctl", &["bootstrap", &domain, &paths.daemon_plist.display().to_string()])?;
    if client::wait_for_daemon(&paths, Duration::from_secs(30)) {
        let status = client::status(&paths)?;
        println!("daemon:   running (pid {}), socket {}", status.pid, paths.socket.display());
        Ok(())
    } else {
        Err(VaultError::Daemon(format!("the daemon didn't answer within 30s; its log is {}", paths.daemon_log.display())))
    }
}

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
        program = xml_escape(&paths.program.display().to_string()),
        watch = xml_escape(&paths.local_backups.display().to_string()),
        log = xml_escape(&owner.mirror_log.display().to_string()),
    )
}

/// `vault install-mirror`: the owner's LaunchAgent that copies backups to the mirror folder.
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
