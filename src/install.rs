//! Installing the vault: `sudo vault install-system` (root) and `vault install-mirror` (the
//! owner). These are the only commands that change the system; both are run by the person at
//! the keyboard, never by an agent or the hub (R3, R17).
//!
//! `install-system` is also how the vault is updated: running it again with a new build replaces
//! the program and restarts the daemon, and keeps everything else.

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::client;
use crate::error::VaultError;
use crate::keyprotect;
use crate::platform;
use crate::store::{self, Account, OwnerPaths, Paths, SystemConfig};
use crate::vault;

pub struct SystemOptions {
    pub for_restore: bool,
    pub owner: Option<String>,
    pub kit: Option<PathBuf>,
    pub mirror_dir: Option<PathBuf>,
    pub yes: bool,
}

fn ask(prompt: &str) -> Result<String, VaultError> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn confirm(prompt: &str) -> Result<bool, VaultError> {
    let answer = ask(&format!("{prompt} [y/N] "))?;
    Ok(matches!(answer.as_str(), "y" | "Y" | "yes" | "Yes"))
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

fn group_exists(gid: u32) -> bool {
    unsafe { !libc::getgrgid(gid).is_null() }
}

fn group_gid(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if group.is_null() { None } else { Some(unsafe { (*group).gr_gid }) }
}

/// Creates the role account `_volgenicvault` with `dscl`, run as root: no password, no login
/// shell, home `/var/empty`, hidden (R17, R33: never `sysadminctl`, which may ask for
/// administrator authentication). Reuses it if it exists and looks right.
fn ensure_role_account() -> Result<Account, VaultError> {
    if let Some(account) = store::role_account() {
        if !store::ROLE_ID_RANGE.contains(&account.uid) || account.shell != "/usr/bin/false" {
            return Err(VaultError::UnsafeVaultFolder(format!(
                "{} exists but isn't the vault's role account (user ID {}, shell {})",
                store::ROLE_USER,
                account.uid,
                account.shell
            )));
        }
        println!("  role account:  {} exists (user ID {})", store::ROLE_USER, account.uid);
        return Ok(account);
    }
    let gid = match group_gid(store::ROLE_USER) {
        Some(gid) if store::ROLE_ID_RANGE.contains(&gid) => gid,
        Some(gid) => {
            return Err(VaultError::UnsafeVaultFolder(format!(
                "a group {} exists with ID {gid}, outside 450-499",
                store::ROLE_USER
            )));
        }
        None => 0,
    };
    let id = store::ROLE_ID_RANGE
        .clone()
        .find(|id| {
            store::account_by_uid(*id).is_none() && (gid == *id || (gid == 0 && !group_exists(*id)))
        })
        .ok_or_else(|| VaultError::Io("no free user and group ID in 450-499".into()))?;
    let id_text = id.to_string();
    let group = format!("/Groups/{}", store::ROLE_USER);
    let user = format!("/Users/{}", store::ROLE_USER);
    let dscl = |args: &[&str]| -> Result<(), VaultError> {
        let mut all = vec!["."];
        all.extend_from_slice(args);
        run("/usr/bin/dscl", &all).map(|_| ())
    };
    if gid == 0 {
        dscl(&["-create", &group])?;
        dscl(&["-create", &group, "PrimaryGroupID", &id_text])?;
        dscl(&["-create", &group, "RealName", "Volgenic Vault"])?;
        dscl(&["-create", &group, "Password", "*"])?;
    }
    dscl(&["-create", &user])?;
    dscl(&["-create", &user, "UniqueID", &id_text])?;
    dscl(&["-create", &user, "PrimaryGroupID", &id_text])?;
    dscl(&["-create", &user, "UserShell", "/usr/bin/false"])?;
    dscl(&["-create", &user, "NFSHomeDirectory", "/var/empty"])?;
    dscl(&["-create", &user, "RealName", "Volgenic Vault"])?;
    dscl(&["-create", &user, "Password", "*"])?;
    dscl(&["-create", &user, "IsHidden", "1"])?;
    let _ = run("/usr/bin/dscacheutil", &["-flushcache"]);
    for _ in 0..40 {
        if let Some(account) = store::role_account() {
            println!("  role account:  {} created (user and group ID {id})", store::ROLE_USER);
            return Ok(account);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(VaultError::Io(format!("{} was created but the user database doesn't show it yet", store::ROLE_USER)))
}

/// Makes a folder owned by `uid:gid` with `mode`, or checks an existing one. An existing folder
/// owned by anyone else is refused, never adopted: something the owner's user made could hold
/// files planted by an agent.
fn ensure_dir(dir: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), VaultError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(VaultError::UnsafeVaultFolder(format!("{} isn't a plain folder", dir.display())));
            }
            if meta.uid() != uid {
                return Err(VaultError::UnsafeVaultFolder(format!(
                    "{} already exists and belongs to user ID {}, not {uid}. Look at what is in it, \
                     remove it, then run install-system again",
                    dir.display(),
                    meta.uid()
                )));
            }
        }
        Err(_) => fs::create_dir(dir)?,
    }
    chown(dir, uid, gid)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), VaultError> {
    let c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| VaultError::Io("bad path".into()))?;
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 {
        return Err(VaultError::Io(format!("chown {} failed", path.display())));
    }
    Ok(())
}

/// Hands every file in the vault folder to the vault's account (install-system writes them as
/// root, before the daemon starts).
fn hand_over_vault_files(paths: &Paths, role: &Account) -> Result<(), VaultError> {
    for entry in fs::read_dir(&paths.dir)? {
        let path = entry?.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            return Err(VaultError::UnsafeVaultFolder(format!("{} is a symbolic link", path.display())));
        }
        chown(&path, role.uid, role.gid)?;
    }
    Ok(())
}

/// Copies this build to the root-owned program path, through a temporary file and a rename.
fn install_program(paths: &Paths, exe: &Path) -> Result<(), VaultError> {
    if exe == paths.program {
        println!("  program:       already running from {}", paths.program.display());
        return Ok(());
    }
    let temp = paths.bin_dir.join(".vault.new");
    let _ = fs::remove_file(&temp);
    let bytes = fs::read(exe)?;
    {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o755).open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    chown(&temp, 0, 0)?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o755))?;
    let installed = platform::signature_of(&temp);
    if !installed.is_the_vaults() {
        let _ = fs::remove_file(&temp);
        return Err(VaultError::Unsigned(installed.describe()));
    }
    fs::rename(&temp, &paths.program)?;
    println!("  program:       {}", paths.program.display());
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

fn owner_of_sudo(owner: Option<&str>) -> Result<OwnerPaths, VaultError> {
    let uid = match owner {
        Some(name) => store::account_by_name(name).map(|a| a.uid).ok_or_else(|| VaultError::Io(format!("no user {name}")))?,
        None => std::env::var("SUDO_UID")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .ok_or_else(|| VaultError::Io("run it with sudo from your own account, or pass --owner".into()))?,
    };
    if uid == 0 {
        return Err(VaultError::Io("the vault's owner can't be root; run sudo from your own account".into()));
    }
    OwnerPaths::for_uid(uid)
}

/// `sudo vault install-system`: the role account, the folders, the program, the Secure Enclave
/// key, the vault and its Recovery Kit, and the daemon. Run again with a new build to update.
pub fn install_system(options: SystemOptions) -> Result<(), VaultError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(VaultError::NotRoot);
    }
    let paths = Paths::system();
    let owner = owner_of_sudo(options.owner.as_deref())?;
    if platform::auto_login_on() {
        return Err(VaultError::AutoLoginOn); // R31
    }
    if !keyprotect::hardware_available() {
        return Err(VaultError::NoSecureEnclave);
    }
    let exe = std::env::current_exe()?.canonicalize()?;
    let signature = platform::signature_of(&exe);
    if !signature.is_the_vaults() {
        return Err(VaultError::Unsigned(signature.describe()));
    }
    let sha = platform::sha256_of(&exe)?;
    let updating = paths.program.exists();
    let has_vault = store::vault_exists(&paths);

    println!("Volgenic vault {} (commit {})", crate::VERSION, crate::GIT_COMMIT);
    println!("  this build:    {}", exe.display());
    println!("  SHA-256:       {sha}");
    println!("  signature:     {}", signature.describe());
    println!("  owner:         {} (user ID {})", owner.name, owner.uid);
    println!();
    println!("Check the commit and SHA-256 against the change you meant to install: this build is");
    println!("about to run as root, and anything that can write where it sits could have swapped it.");
    println!();
    if updating {
        println!("This UPDATES the installed vault: it replaces the program and restarts the daemon.");
        println!("The vault, its key, its backups and the audit log stay as they are.");
    } else {
        println!("This installs the vault as its own macOS account, so agents can reach its socket but");
        println!("not its files:");
        println!("  - creates the hidden role account {} (no password, can't log in);", store::ROLE_USER);
        println!("  - installs the program in {} (only root can change it);", paths.bin_dir.display());
        println!("  - makes this Mac's Secure Enclave key (no dialog: it needs no fingerprint or password);");
        if options.for_restore {
            println!("  - makes no vault: run `vault restore FILE` afterwards;");
        } else {
            println!("  - makes the vault and writes its Recovery Kit to your home folder;");
        }
        println!("  - starts the daemon {}. macOS shows a \"Background Items Added\"", store::DAEMON_LABEL);
        println!("    notification; nothing to click.");
    }
    if !options.yes && !confirm("Go ahead?")? {
        println!("Nothing changed.");
        return Ok(());
    }

    // Answers first, so nothing is half-installed while the person types.
    let mut kit_and_mirror = None;
    if !has_vault && !options.for_restore && !keyprotect::wrapped_exists(&paths.dir) {
        let kit = match options.kit {
            Some(path) => owner.expand(&path.display().to_string()),
            None => {
                println!();
                println!("The Recovery Kit holds the key that opens your backups. Print it or save it in your");
                println!("password manager, then confirm it with `vault confirm-kit`; that deletes the file.");
                println!("Keep the default: on the Desktop or in Documents or Downloads, macOS may first ask");
                println!("whether Terminal may access that folder.");
                let answer = ask(&format!("Save the Recovery Kit to [{}]: ", owner.default_kit.display()))?;
                if answer.is_empty() { owner.default_kit.clone() } else { owner.expand(&answer) }
            }
        };
        let mirror = match options.mirror_dir {
            Some(path) => owner.expand(&path.display().to_string()),
            None => {
                let suggested = owner.icloud_backups();
                println!();
                println!("The daemon writes an encrypted backup after every change, in");
                println!("{}. A small agent in your login copies each one", paths.local_backups.display());
                println!("off this Mac's disk, so a lost or stolen Mac doesn't take them along.");
                println!("Suggested: iCloud Drive (Apple stores only ciphertext; Volgenic stores nothing).");
                let answer = ask(&format!("Copy backups to [{}]: ", suggested.display()))?;
                if answer.is_empty() { suggested } else { owner.expand(&answer) }
            }
        };
        kit_and_mirror = Some((kit, mirror));
    }

    println!();
    let role = ensure_role_account()?;
    ensure_dir(&paths.base, 0, 0, 0o755)?;
    ensure_dir(&paths.bin_dir, 0, 0, 0o755)?;
    ensure_dir(&paths.root_dir, 0, 0, 0o700)?;
    ensure_dir(&paths.dir, role.uid, role.gid, 0o700)?;
    ensure_dir(&paths.local_backups, role.uid, role.gid, 0o755)?;
    ensure_dir(&paths.socket_dir, role.uid, role.gid, 0o755)?;
    ensure_dir(&paths.log_dir, 0, 0, 0o755)?;
    println!("  folders:       {} (root's; the vault's own folders are {}'s)", paths.base.display(), store::ROLE_USER);

    // Stop the daemon before touching the program or the vault.
    let _ = Command::new("/bin/launchctl").args(["bootout", &format!("system/{}", store::DAEMON_LABEL)]).output();
    install_program(&paths, &exe)?;

    let se_public = if keyprotect::se_key_exists(&paths.root_dir) {
        println!("  Secure Enclave key: kept (root's, in {})", paths.root_dir.display());
        keyprotect::load_public(&paths.root_dir)?
    } else {
        let public = keyprotect::create_se_key(&paths.root_dir)?;
        println!("  Secure Enclave key: made for this Mac (handle in {}, root only)", paths.root_dir.display());
        public
    };
    store::write_system_config(
        &paths,
        &SystemConfig {
            owner_uid: owner.uid,
            role_uid: role.uid,
            role_gid: role.gid,
            installed_at: crate::now_rfc3339(),
            installed_version: format!("{} ({})", crate::VERSION, crate::GIT_COMMIT),
        },
    )?;

    let mut kit_written = None;
    if let Some((kit, mirror)) = kit_and_mirror {
        let report = vault::init(&paths, &se_public, &kit, owner.uid, &mirror)?;
        println!("  vault:         {} made", report.vault_id);
        println!("  recovery key:  fingerprint {}", report.recovery_fingerprint);
        println!("  Recovery Kit:  {}", report.kit_path.display());
        println!("  backups:       {}, copied to {}", paths.local_backups.display(), report.mirror_dir.display());
        kit_written = Some(report.kit_path);
    } else if has_vault {
        println!("  vault:         kept");
    } else {
        println!("  vault:         none yet (restore one with `vault restore FILE`)");
    }
    hand_over_vault_files(&paths, &role)?;

    let plist = daemon_plist(&paths);
    store::write_atomic_mode(&paths.daemon_plist, plist.as_bytes(), 0o644)?;
    chown(&paths.daemon_plist, 0, 0)?;
    let _ = Command::new("/bin/launchctl").args(["enable", &format!("system/{}", store::DAEMON_LABEL)]).output();
    run("/bin/launchctl", &["bootstrap", "system", &paths.daemon_plist.display().to_string()])?;
    println!("  daemon:        {} started; log {}", store::DAEMON_LABEL, paths.daemon_log.display());

    if client::wait_for_daemon(&paths, Duration::from_secs(60)) {
        let status = client::status(&paths)?;
        println!("  daemon answers as {} (user ID {}), pid {}", store::ROLE_USER, status.uid, status.pid);
        if let Some(vault) = &status.vault {
            match &vault.last_backup {
                Some(b) if b.ok => println!("  backup:        generation {} OK ({})", b.generation, b.detail),
                Some(b) => println!("  backup:        FAILED: {}", b.detail),
                None => println!("  backup:        none yet"),
            }
        }
    } else {
        println!("  daemon:        NOT answering after 60s. Its log: {}", paths.daemon_log.display());
    }

    let rules = platform::passwordless_sudo_rules();
    println!();
    if rules.is_empty() {
        println!("Passwordless sudo: none found in /etc/sudoers or /etc/sudoers.d.");
    } else {
        println!("Passwordless sudo rules on this Mac. Any of them an agent can use gives it root, and");
        println!("root opens the vault. Check each one:");
        for rule in &rules {
            println!("  {rule}");
        }
    }

    println!();
    if let Some(kit) = kit_written {
        println!("Next, as yourself (no sudo):");
        println!("  1. vault install-mirror     copies the backups to your mirror folder (one macOS dialog)");
        println!("  2. open -e {:?}   then print it or save the key", kit.display().to_string());
        println!("  3. vault confirm-kit        the vault stores no secret until you do");
    } else if updating {
        println!("Updated. Nothing else to do.");
    }
    Ok(())
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
    let paths = Paths::system();
    let meta = fs::symlink_metadata(&paths.program).map_err(|_| VaultError::NotInstalled)?;
    if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(VaultError::UnsafeVaultFolder(format!("{} isn't root's", paths.program.display())));
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
