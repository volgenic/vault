//! `vault`: the command-line tool and the background `serve` process, one binary.
//!
//! Any agent on this Mac can run this program, so no command prints a secret value (R26). It
//! can't: `SecretValue::expose` is private to the library. Values are read at a hidden prompt
//! or from standard input, never from arguments or the environment (R2).

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use vault::audit::{self, AuditEvent};
use vault::error::VaultError;
use vault::model::Kind;
use vault::rules;
use vault::secret::SecretValue;
use vault::store::{self, Paths};
use vault::vault::{self as ops, InitOptions, NewSecret, Vault};

#[derive(Parser)]
#[command(name = "vault", version, about = "Volgenic's vault: agents use your secrets without seeing them.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Set up the vault on this Mac: Secure Enclave key, Recovery Kit, backup folder.
    Init {
        /// Where to save the Recovery Kit (asked if left out).
        #[arg(long)]
        kit: Option<PathBuf>,
        /// Folder for encrypted backups (asked if left out; iCloud Drive is suggested).
        #[arg(long)]
        backup_dir: Option<PathBuf>,
    },
    /// Confirm the Recovery Kit by pasting the recovery key back. Needed before any secret.
    ConfirmKit,
    /// Add a secret. The value is read at a hidden prompt (or from standard input).
    Add {
        name: String,
        #[arg(long, value_enum)]
        kind: KindArg,
        /// The site the secret belongs to (defaults to the rule's host for an API key).
        #[arg(long)]
        site: Option<String>,
        /// API key: the one host the key may be sent to, e.g. api.openai.com.
        #[arg(long)]
        host: Option<String>,
        /// API key: port (default 443).
        #[arg(long)]
        port: Option<u16>,
        /// API key: allowed method(s), e.g. GET or GET,POST.
        #[arg(long = "method")]
        methods: Vec<String>,
        /// API key: path prefix, matched on whole segments, e.g. /v1/models.
        #[arg(long, default_value = "/")]
        path: String,
        /// API key: the header and format, e.g. "Authorization: Bearer {key}".
        #[arg(long, default_value = "Authorization: Bearer {key}")]
        header: String,
        /// Login: the username.
        #[arg(long)]
        username: Option<String>,
        /// Don't ask for confirmation (needed when the value comes from standard input).
        #[arg(long)]
        yes: bool,
    },
    /// Delete a secret. Earlier backups still hold it.
    Delete {
        name: String,
        #[arg(long)]
        yes: bool,
    },
    /// List secrets: names, kinds and sites only.
    List,
    /// Show the vault's state. Information only; never a value.
    Status,
    /// Show the audit log and check its hash chain.
    Audit {
        /// Show every line, not just the last 25.
        #[arg(long)]
        all: bool,
    },
    /// Check a backup (the newest by default) against the vault.
    VerifyBackup {
        #[arg(long)]
        file: Option<PathBuf>,
        /// Also prove the Recovery Kit opens it (asks for the recovery key, hidden).
        #[arg(long)]
        with_recovery_key: bool,
    },
    /// Restore a backup into a fresh vault on this Mac, with the recovery key.
    Restore { file: PathBuf },
    /// Remove this Mac's vault so a backup can be restored (needs the recovery key).
    Reset,
    /// Install and start the LaunchAgent that runs `vault serve` at login.
    InstallAgent,
    /// Serve agents on the local socket (run by the LaunchAgent).
    Serve,
}

#[derive(Clone, Copy, ValueEnum)]
enum KindArg {
    #[value(name = "api-key")]
    ApiKey,
    Login,
    #[value(name = "2fa")]
    TwoFactor,
}

fn main() -> ExitCode {
    vault::platform::harden_process();
    let cli = Cli::parse();
    let paths = match Paths::for_current_user() {
        Ok(paths) => paths,
        Err(error) => return fail(&error),
    };
    let result = match cli.command {
        Command::Init { kit, backup_dir } => init(&paths, kit, backup_dir),
        Command::ConfirmKit => confirm_kit(&paths),
        Command::Add { name, kind, site, host, port, methods, path, header, username, yes } => {
            add(&paths, name, kind, site, host, port, methods, path, header, username, yes)
        }
        Command::Delete { name, yes } => delete(&paths, &name, yes),
        Command::List => list(&paths),
        Command::Status => status(&paths),
        Command::Audit { all } => show_audit(&paths, all),
        Command::VerifyBackup { file, with_recovery_key } => verify_backup(&paths, file, with_recovery_key),
        Command::Restore { file } => restore(&paths, &file),
        Command::Reset => reset(&paths),
        Command::InstallAgent => install_agent(&paths),
        Command::Serve => vault::server::serve(&paths),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&error),
    }
}

fn fail(error: &VaultError) -> ExitCode {
    eprintln!("vault: {error}");
    ExitCode::FAILURE
}

/// Reads a line the person types, shown as they type it (paths, yes/no).
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

/// Reads a value without echoing it: at a hidden prompt on the terminal, or from standard input
/// when that isn't a terminal. Never from arguments or the environment (R2, R26).
fn read_hidden(prompt: &str) -> Result<SecretValue, VaultError> {
    if std::io::stdin().is_terminal() {
        let text = rpassword::prompt_password(prompt)?;
        Ok(SecretValue::from_string(text))
    } else {
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text)?;
        let trimmed = text.trim_end_matches(['\n', '\r']).to_string();
        zeroize::Zeroize::zeroize(&mut text);
        Ok(SecretValue::from_string(trimmed))
    }
}

fn expand_home(paths: &Paths, text: &str) -> PathBuf {
    match text.strip_prefix("~/") {
        Some(rest) => paths.home.join(rest),
        None if text == "~" => paths.home.clone(),
        None => PathBuf::from(text),
    }
}

fn init(paths: &Paths, kit: Option<PathBuf>, backup_dir: Option<PathBuf>) -> Result<(), VaultError> {
    println!("Setting up Volgenic's vault on this Mac.\n");
    // The kit's default home is the vault folder: outside Desktop, Documents and Downloads,
    // so writing it can't raise a macOS file-access dialog.
    let default_kit = paths.dir.join("Volgenic Vault Recovery Kit.txt");
    let kit_path = match kit {
        Some(path) => path,
        None => {
            println!("The Recovery Kit holds the key that opens your backups. Print it or save it in");
            println!("your password manager, then confirm it; the vault deletes the file after that.");
            let answer = ask(&format!("Save the Recovery Kit to [{}]: ", default_kit.display()))?;
            if answer.is_empty() { default_kit } else { expand_home(paths, &answer) }
        }
    };
    let suggested = paths.icloud_backups().unwrap_or_else(|| paths.local_backups.clone());
    let backup_dir = match backup_dir {
        Some(path) => path,
        None => {
            println!();
            println!("Backups are encrypted to your recovery key and written after every change.");
            println!("Keep them off this Mac's disk so a lost or stolen Mac doesn't take them along.");
            if paths.icloud_backups().is_some() {
                println!("Suggested: iCloud Drive (Apple stores only ciphertext; Volgenic stores nothing).");
                println!("If Terminal hasn't used iCloud Drive before, macOS may now ask once whether");
                println!("Terminal may access files in iCloud Drive. That is for this backup folder: click");
                println!("Allow. It is the only dialog setup can show; the vault never uses the Keychain.");
            }
            let answer = ask(&format!("Backup folder [{}]: ", suggested.display()))?;
            if answer.is_empty() { suggested } else { expand_home(paths, &answer) }
        }
    };
    println!();
    let report = ops::init(paths, &InitOptions { kit_path, backup_dir })?;
    println!("Vault created: {}", report.vault_id);
    println!("  vault key:        wrapped by this Mac's Secure Enclave (key.se in the vault folder)");
    println!("  Recovery Kit:     {}", report.kit_path.display());
    println!("  recovery key:     fingerprint {}", report.recovery_fingerprint);
    println!("  backups:          {}", report.backup_dir.display());
    print_backup(&report.backup);
    println!();
    println!("Next: open the kit (open -e {:?}),", report.kit_path.display().to_string());
    println!("print it or save the key in your password manager, then run");
    println!("  vault confirm-kit");
    println!("The vault stores no secret until the kit is confirmed.");
    Ok(())
}

fn print_backup(status: &vault::model::BackupStatus) {
    if status.ok {
        println!("  backup:           generation {} written, read back and decrypted OK", status.generation);
        println!("                    {}", status.file);
    } else {
        println!("  backup:           FAILED: {}", status.detail);
    }
}

fn confirm_kit(paths: &Paths) -> Result<(), VaultError> {
    let mut vault = Vault::open(paths)?;
    if vault.kit_confirmed() {
        return Err(VaultError::KitAlreadyConfirmed);
    }
    let typed = read_hidden("Paste the recovery key from the kit (AGE-SECRET-KEY-1...), hidden: ")?;
    let status = vault.confirm_kit(typed)?;
    println!("Recovery Kit confirmed; the kit file on this Mac is deleted. The vault can store secrets now.");
    print_backup(&status);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add(
    paths: &Paths,
    name: String,
    kind: KindArg,
    site: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    methods: Vec<String>,
    path: String,
    header: String,
    username: Option<String>,
    yes: bool,
) -> Result<(), VaultError> {
    let mut vault = Vault::open(paths)?;
    if !vault.kit_confirmed() {
        return Err(VaultError::KitNotConfirmed);
    }
    let kind = match kind {
        KindArg::ApiKey => Kind::ApiKey,
        KindArg::Login => Kind::Login,
        KindArg::TwoFactor => Kind::TwoFactor,
    };
    let rule = match kind {
        Kind::ApiKey => {
            let host = host.ok_or_else(|| VaultError::InvalidRule("an API key needs --host".into()))?;
            let methods = if methods.is_empty() { vec!["GET".to_string()] } else { methods };
            Some(rules::parse_rule(&host, port, &methods, &path, &header)?)
        }
        _ => None,
    };
    let site = match (&site, &rule) {
        (Some(site), _) => site.clone(),
        (None, Some(rule)) => rule.host.clone(),
        (None, None) => return Err(VaultError::InvalidSecret("give --site".into())),
    };

    println!("Adding {} {name:?} for {site}", kind.label());
    if let Some(rule) = &rule {
        println!("  rule: {}", rule.describe());
        println!("  the key is sent only there, only in that header; redirects are never followed");
    }
    if let Some(username) = &username {
        println!("  username: {username}");
    }
    let stdin_value = !std::io::stdin().is_terminal();
    if stdin_value && !yes {
        return Err(VaultError::InvalidSecret("reading the value from standard input needs --yes".into()));
    }
    if !yes && !confirm("Save it?")? {
        println!("Nothing saved.");
        return Ok(());
    }
    let prompt = match kind {
        Kind::ApiKey => "API key (hidden): ",
        Kind::Login => "Password (hidden): ",
        Kind::TwoFactor => "2FA seed, base32 or otpauth:// link (hidden): ",
    };
    let value = read_hidden(prompt)?;
    let (summary, status) = vault.add(NewSecret { name, kind, site, rule, username, value })?;
    println!("Saved {} {:?} for {}.", summary.kind.label(), summary.name, summary.site);
    print_backup(&status);
    Ok(())
}

fn delete(paths: &Paths, name: &str, yes: bool) -> Result<(), VaultError> {
    let mut vault = Vault::open(paths)?;
    if !yes && !confirm(&format!("Delete {name:?}? Earlier backups keep it."))? {
        println!("Nothing deleted.");
        return Ok(());
    }
    let status = vault.delete(name)?;
    println!("Deleted {name:?}.");
    print_backup(&status);
    Ok(())
}

fn list(paths: &Paths) -> Result<(), VaultError> {
    let vault = Vault::open(paths)?;
    let secrets = vault.summaries();
    vault.audit(AuditEvent::new("list", "ok"))?;
    if secrets.is_empty() {
        println!("No secrets yet.");
        return Ok(());
    }
    println!("{:<24} {:<8} SITE", "NAME", "KIND");
    for secret in secrets {
        println!("{:<24} {:<8} {}", secret.name, secret.kind.label(), secret.site);
    }
    Ok(())
}


fn status(paths: &Paths) -> Result<(), VaultError> {
    let report = ops::status(paths);
    println!("Volgenic vault {}", vault::VERSION);
    println!("  program signature: {}", report.signature);
    println!("  vault folder:      {}", report.vault_folder.display());
    println!("  Secure Enclave:    {}", if report.secure_enclave { "available" } else { "NOT available" });
    println!("  key protection:    {}", report.key_protection);
    println!("  protected key:     {}", if report.key_file { "present (key.se)" } else { "absent" });
    println!("  Keychain:          not used (no Keychain dialogs, ever)");
    println!(
        "  automatic login:   {}",
        if report.auto_login_on { "ON: the vault refuses to run until it is turned off" } else { "off (required)" }
    );
    println!("  FileVault:         {} (information only)", report.filevault);
    println!("  serve:             {}", if report.serve_running { "running, socket answering" } else { "not running" });
    if !report.vault_exists {
        println!("\nNo vault on this Mac yet. Run `vault init`.");
        return Ok(());
    }
    if let Some(error) = &report.open_error {
        println!("\nThe vault exists but can't be opened: {error}");
        return Ok(());
    }
    if let Some(opened) = &report.opened {
        println!("\nVault {}", opened.vault_id);
        println!("  created:           {}", opened.created_at);
        println!("  recovery key:      fingerprint {}", opened.recovery_fingerprint);
        println!(
            "  Recovery Kit:      {}",
            if opened.kit_confirmed { "confirmed" } else { "NOT confirmed: run `vault confirm-kit`; no secrets until then" }
        );
        let kinds: Vec<String> = opened.by_kind.iter().map(|(k, n)| format!("{n} {}", k.label())).collect();
        println!("  secrets:           {} ({})", opened.secrets, kinds.join(", "));
        println!("  changes so far:    {}", opened.generation);
        println!("  backup folder:     {}", opened.backup_dir);
        match &opened.last_backup {
            Some(backup) if backup.ok => println!(
                "  last backup:       OK, generation {} at {}, read back and decrypted",
                backup.generation, backup.at
            ),
            Some(backup) => println!("  last backup:       FAILED at {}: {} (changes refused until a backup succeeds)", backup.at, backup.detail),
            None => println!("  last backup:       none yet"),
        }
        match &opened.audit_chain {
            Ok(lines) => println!("  audit log:         {lines} lines, hash chain intact"),
            Err(error) => println!("  audit log:         PROBLEM: {error}"),
        }
        if !opened.recent_changes.is_empty() {
            println!("  recent changes:");
            for change in &opened.recent_changes {
                println!("    {change}");
            }
        }
    }
    Ok(())
}

fn show_audit(paths: &Paths, all: bool) -> Result<(), VaultError> {
    let (lines, chain) = match audit::read_and_verify(&paths.audit_log) {
        Ok((lines, _)) => (lines, Ok(())),
        Err(error) => (Vec::new(), Err(error)),
    };
    if let Err(error) = &chain {
        println!("PROBLEM: {error}");
        return Ok(());
    }
    let skip = if all { 0 } else { lines.len().saturating_sub(25) };
    for line in &lines[skip..] {
        let e = &line.event;
        let mut text = format!("{}  {:<14} {:<22}", line.t, e.event, e.name.clone().unwrap_or_default());
        if let (Some(method), Some(host)) = (&e.method, &e.host) {
            text.push_str(&format!(" {method} https://{host}{}", e.path.clone().unwrap_or_default()));
        } else if let Some(method) = &e.method {
            text.push_str(&format!(" {method} {}", e.path.clone().unwrap_or_default()));
        }
        if let Some(status) = e.status {
            text.push_str(&format!(" -> {status}"));
        }
        text.push_str(&format!("  {}", e.outcome));
        if let Some(detail) = &e.detail {
            text.push_str(&format!("  ({detail})"));
        }
        if let Some(program) = &e.peer_program {
            text.push_str(&format!("  [caller pid {} {}]", e.peer_pid.unwrap_or(0), program));
        }
        println!("{text}");
    }
    println!("-- {} lines, hash chain intact{}", lines.len(), if skip > 0 { format!("; showing the last {}", lines.len() - skip) } else { String::new() });
    if store::vault_exists(paths) {
        if let Ok(vault) = Vault::open(paths) {
            let _ = vault.audit(AuditEvent::new("audit", "ok"));
        }
    }
    Ok(())
}

fn verify_backup(paths: &Paths, file: Option<PathBuf>, with_recovery_key: bool) -> Result<(), VaultError> {
    let vault = Vault::open(paths)?;
    let recovery = if with_recovery_key {
        Some(read_hidden("Recovery key (AGE-SECRET-KEY-1...), hidden: ")?)
    } else {
        None
    };
    let report = vault.verify_backup(file, recovery)?;
    println!("Backup {}", report.file.display());
    println!("  generation {}, written {}{}", report.generation, report.written_at, if report.newest { " (newest)" } else { "" });
    println!("  decrypted with the vault's check key: OK, {} secrets", report.secrets);
    println!(
        "  matches the vault: {}",
        if report.matches_vault { "yes, every name, rule and value" } else { "NO (an older generation, or the vault changed since)" }
    );
    match report.recovery_key_opens {
        Some(true) => println!("  recovery key opens it: yes"),
        Some(false) => println!("  recovery key opens it: NO"),
        None => println!("  recovery key: not checked (add --with-recovery-key)"),
    }
    if !report.matches_vault && report.newest {
        return Err(VaultError::BackupMismatch);
    }
    if report.recovery_key_opens == Some(false) {
        return Err(VaultError::WrongRecoveryKey);
    }
    Ok(())
}

fn restore(paths: &Paths, file: &Path) -> Result<(), VaultError> {
    let typed = read_hidden("Recovery key (AGE-SECRET-KEY-1...), hidden: ")?;
    let report = ops::restore(paths, file, typed)?;
    println!("Restored vault {} from generation {}.", report.vault_id, report.from_generation);
    println!("  new Secure Enclave key and new vault key made on this Mac");
    for secret in &report.secrets {
        println!("  {:<24} {:<8} {}", secret.name, secret.kind.label(), secret.site);
    }
    print_backup(&report.backup);
    Ok(())
}

fn reset(paths: &Paths) -> Result<(), VaultError> {
    println!("This removes the vault from this Mac (its vault file and key.se) so a backup");
    println!("can be restored. Backups and the audit log stay. It needs the recovery key, and it");
    println!("only goes ahead if the newest backup opens with that key and matches the vault.");
    if !confirm("Go ahead?")? {
        println!("Nothing changed.");
        return Ok(());
    }
    let typed = read_hidden("Recovery key (AGE-SECRET-KEY-1...), hidden: ")?;
    let newest = ops::reset(paths, typed)?;
    println!("Vault removed from this Mac. Restore it with:");
    println!("  vault restore {:?}", newest.display().to_string());
    Ok(())
}

fn install_agent(paths: &Paths) -> Result<(), VaultError> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let log_dir = paths.log_file.parent().map(Path::to_path_buf).unwrap_or_default();
    std::fs::create_dir_all(&log_dir)?;
    if let Some(dir) = paths.launch_agent.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.volgenic.vault</string>
  <key>ProgramArguments</key>
  <array><string>{exe}</string><string>serve</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
        exe = xml_escape(&exe.display().to_string()),
        log = xml_escape(&paths.log_file.display().to_string()),
    );
    store::write_atomic(&paths.launch_agent, plist.as_bytes())?;
    let domain = format!("gui/{}", unsafe { libc::getuid() });
    let _ = std::process::Command::new("/bin/launchctl")
        .args(["bootout", &format!("{domain}/com.volgenic.vault")])
        .output();
    let out = std::process::Command::new("/bin/launchctl")
        .args(["bootstrap", &domain])
        .arg(&paths.launch_agent)
        .output()?;
    if !out.status.success() {
        return Err(VaultError::Io(format!(
            "launchctl bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    println!("LaunchAgent com.volgenic.vault installed and started:");
    println!("  {}", paths.launch_agent.display());
    println!("  runs {} serve at login; log: {}", exe.display(), paths.log_file.display());
    Ok(())
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
