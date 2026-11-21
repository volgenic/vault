//! `vault`: the command-line tool, the daemon and the backup mirror, one binary.
//!
//! The vault's daemon runs as the owner: a LaunchAgent in his login on macOS, a systemd user
//! service started at boot on Linux. Every command here except the two installers is a request
//! to the daemon over its socket (R13, R26). Any agent on the machine can run it, so no command
//! prints a secret value: replies carry none (R4). Values are read at a hidden prompt or from standard input, never from
//! arguments or the environment (R2).

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

use vault::client;
use vault::error::VaultError;
use vault::install;
use vault::model::{BackupStatus, Kind, SecretRef};
use vault::platform::{self, MACHINE};
use vault::protocol::RuleInput;
use vault::secret::SecretValue;
use vault::store::{self, Paths};

#[derive(Parser)]
#[command(name = "vault", version = vault::VERSION_LINE, about = "Volgenic's vault: agents use your secrets without seeing them.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Install or update the vault for your user: no sudo, no questions. Makes the vault if
    /// there is none, and starts its daemon in your login.
    Install {
        /// Install without making a vault, to restore one from a backup file next.
        #[arg(long)]
        for_restore: bool,
        /// Print one JSON object for a program instead of prose. Never prompts.
        #[arg(long)]
        json: bool,
    },
    /// Install the agent in your login that copies backups to the mirror folder (no sudo).
    InstallMirror {
        #[arg(long)]
        yes: bool,
    },
    /// Optional: confirm the Recovery Kit by pasting the recovery key back; deletes the kit file.
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
        /// App secret: the application it belongs to.
        #[arg(long)]
        app: Option<String>,
        /// App secret: it may be leased to builds (sealed to one build's own key, for at most a
        /// day). Without it the secret is stored and listed only. Set only when it is added.
        #[arg(long)]
        leasable: bool,
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
    /// Make a wallet, or change its caps. The vault makes the wallet's key itself and never
    /// shows it; both ask for the recovery key, since only you may set what a wallet can spend.
    Wallet {
        #[command(subcommand)]
        action: WalletCommand,
    },
    /// Rename a secret. It keeps its id, rule and value; its version goes up by one.
    Rename { name: String, new_name: String },
    /// List secrets: ids, names, kinds, sites and versions only.
    List,
    /// Whether each Claude plan's token works, has expired or was refused, by name only.
    Health,
    /// Show the vault's state. Information only; never a value.
    Status {
        /// Print one JSON object for a program (no secret names, no values).
        #[arg(long)]
        json: bool,
    },
    /// Show the audit log and check its hash chain.
    Audit {
        /// Show every line, not just the last 25.
        #[arg(long)]
        all: bool,
    },
    /// Have the daemon decrypt the newest backup and compare it with the vault.
    VerifyBackup {
        /// Also prove the Recovery Kit opens it (asks for the recovery key, hidden).
        #[arg(long)]
        with_recovery_key: bool,
    },
    /// Have the daemon write (or re-check) the current backup now, e.g. after a failure.
    Backup,
    /// Restore a backup into an empty vault here, with the recovery key. Without FILE,
    /// restores the copy `vault reset` kept.
    Restore { file: Option<PathBuf> },
    /// Remove this machine's vault so a backup can be restored (needs the recovery key).
    Reset,
    /// The vault's background part, run as you by launchd (macOS) or systemd (Linux).
    #[command(hide = true)]
    Daemon,
    /// Copy backups to the mirror folder (run by the owner's LaunchAgent).
    #[command(hide = true)]
    Mirror,
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Make a wallet: a new key, made in this vault and never shown, and its address to fund.
    /// Its only use is signing token payments within the caps you set here.
    Create {
        name: String,
        /// ethereum, solana or tron; or sepolia, solana_devnet or tron_nile (test networks) for a
        /// dry run.
        #[arg(long, default_value = "ethereum")]
        chain: String,
        /// The most one payment may move, in US dollars (USDC and USDT count one for one).
        #[arg(long)]
        per_payment: String,
        /// The most the payments of any 24 hours may move, in US dollars.
        #[arg(long)]
        daily: String,
        #[command(flatten)]
        fees: FeeCapArgs,
    },
    /// Change a wallet's caps. Caps you leave out stay as they are.
    Caps {
        name: String,
        #[arg(long)]
        per_payment: Option<String>,
        #[arg(long)]
        daily: Option<String>,
        #[command(flatten)]
        fees: FeeCapArgs,
    },
}

/// A wallet's fee caps, each in its chain's own terms; only the wallet's chain's may be given.
/// Left out when making a wallet, each takes the default shown.
#[derive(Args)]
struct FeeCapArgs {
    /// Ethereum: the highest fee per gas any signed transaction may offer, in gwei [default: 100].
    #[arg(long)]
    max_fee_gwei: Option<String>,
    /// Ethereum: the most the fees of any 24 hours could come to, in ETH, each payment counted at
    /// its worst [default: 0.02].
    #[arg(long)]
    daily_fees_eth: Option<String>,
    /// Tron: the highest fee_limit (TRX it may burn for energy) any transaction may carry, in TRX
    /// [default: 30].
    #[arg(long)]
    max_fee_limit_trx: Option<String>,
    /// Tron: the most the fees of any 24 hours could come to, in TRX, each payment counted at its
    /// fee_limit and bandwidth [default: 300].
    #[arg(long)]
    daily_fees_trx: Option<String>,
    /// Solana: the highest priority fee any transaction may offer, in micro-lamports per compute
    /// unit [default: 1000000].
    #[arg(long)]
    max_priority_fee_micro_lamports: Option<String>,
    /// Solana: the most the fees of any 24 hours could come to, in SOL, each payment counted at its
    /// worst, a recipient's new token account's rent included [default: 0.05].
    #[arg(long)]
    daily_fees_sol: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum KindArg {
    #[value(name = "api-key")]
    ApiKey,
    Login,
    #[value(name = "2fa")]
    TwoFactor,
    #[value(name = "claude_plan", alias = "claude-plan")]
    ClaudePlan,
    /// A Codex login: its auth.json, read whole from standard input with --yes.
    #[value(name = "codex_login")]
    CodexLogin,
    /// A Grok Build login: its auth.json, read whole from standard input with --yes.
    #[value(name = "grok_login")]
    GrokLogin,
    /// A Google AI Pro or Ultra login: agy's token file (antigravity-cli/antigravity-oauth-token),
    /// read whole from standard input with --yes.
    #[value(name = "google_ai_login")]
    GoogleAiLogin,
    /// Your real name, address, birthday and phone: asked one field at a time, or v1's JSON
    /// object read from standard input with --yes.
    #[value(name = "personal_details")]
    PersonalDetails,
    /// One of an application's build or deploy secrets (an npm token, a database URL), for the
    /// application --app names. Used only by `lease`, sealed to one build's own key, and only with
    /// --leasable.
    #[value(name = "app_secret")]
    AppSecret,
}

fn main() -> ExitCode {
    platform::harden_process();
    let cli = Cli::parse();
    let paths = Paths::current();
    let result = match cli.command {
        Command::Install { for_restore, json } => install::install(for_restore, json),
        Command::InstallMirror { yes } => install::install_mirror(yes),
        Command::ConfirmKit => confirm_kit(&paths),
        Command::Add { name, kind, site, host, port, methods, path, header, username, app, leasable, yes } => {
            add(&paths, name, kind, site, host, port, methods, path, header, username, app, leasable, yes)
        }
        Command::Delete { name, yes } => delete(&paths, &name, yes),
        Command::Rename { name, new_name } => rename(&paths, &name, &new_name),
        Command::Wallet { action: WalletCommand::Create { name, chain, per_payment, daily, fees } } => {
            wallet_create(&paths, &name, &chain, &per_payment, &daily, &fees)
        }
        Command::Wallet { action: WalletCommand::Caps { name, per_payment, daily, fees } } => {
            wallet_caps(&paths, &name, per_payment, daily, &fees)
        }
        Command::List => list(&paths),
        Command::Health => health(&paths),
        Command::Status { json: true } => status_json(&paths),
        Command::Status { json: false } => status(&paths),
        Command::Audit { all } => show_audit(&paths, all),
        Command::VerifyBackup { with_recovery_key } => verify_backup(&paths, with_recovery_key),
        Command::Backup => backup_now(&paths),
        Command::Restore { file } => restore(&paths, file),
        Command::Reset => reset(&paths),
        Command::Daemon => vault::server::run(),
        Command::Mirror => vault::mirror::run(),
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

/// Reads a line the person types, shown as they type it (yes/no).
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

fn print_backup(status: &BackupStatus) {
    if status.ok {
        println!("  backup:           generation {} OK ({}, by the daemon)", status.generation, status.detail);
        println!("                    {}", status.file);
    } else {
        println!("  backup:           FAILED: {}", status.detail);
    }
}

/// Deletes the kit file `vault install` wrote in the owner's home, after the daemon confirms.
fn delete_kit(kit: Option<&str>) {
    match kit {
        Some(kit) => match vault::vault::wipe_file(std::path::Path::new(kit)) {
            Ok(()) => println!("  kit file deleted: {kit}"),
            Err(error) => println!("  couldn't delete the kit file {kit}: {error}. Delete it yourself."),
        },
        None => {}
    }
}

fn confirm_kit(paths: &Paths) -> Result<(), VaultError> {
    let status = client::status(paths)?;
    let vault = status.vault.ok_or(VaultError::NotInitialized)?;
    if vault.kit_confirmed {
        return Err(VaultError::KitAlreadyConfirmed);
    }
    let typed = read_hidden("Paste the recovery key from the kit (AGE-SECRET-KEY-1...), hidden: ")?;
    let reply = client::confirm_kit(paths, &typed)?;
    drop(typed);
    println!("Recovery Kit confirmed. The vault can store secrets now.");
    delete_kit(reply.kit_path.as_deref());
    print_backup(&reply.backup);
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
    app: Option<String>,
    leasable: bool,
    yes: bool,
) -> Result<(), VaultError> {
    let status = client::status(paths)?;
    status.vault.ok_or(VaultError::NotInitialized)?;
    let kind = match kind {
        KindArg::ApiKey => Kind::ApiKey,
        KindArg::Login => Kind::Login,
        KindArg::TwoFactor => Kind::TwoFactor,
        KindArg::ClaudePlan => Kind::ClaudePlan,
        KindArg::CodexLogin => Kind::CodexLogin,
        KindArg::GrokLogin => Kind::GrokLogin,
        KindArg::GoogleAiLogin => Kind::GoogleAiLogin,
        KindArg::PersonalDetails => Kind::PersonalDetails,
        KindArg::AppSecret => Kind::AppSecret,
    };
    match (kind, &app) {
        (Kind::AppSecret, None) => return Err(VaultError::InvalidSecret("an app secret needs --app".into())),
        (Kind::AppSecret, Some(_)) => {}
        (_, Some(_)) => return Err(VaultError::InvalidSecret("--app is for --kind app_secret only".into())),
        (_, None) if leasable => {
            return Err(VaultError::InvalidSecret("--leasable is for --kind app_secret only".into()));
        }
        (_, None) => {}
    }
    // The rule is checked here for the person to read, and again by the daemon, which never
    // takes a ready-made rule (R7).
    let rule_input = match kind {
        Kind::ApiKey => {
            let host = host.ok_or_else(|| VaultError::InvalidRule("an API key needs --host".into()))?;
            let methods = if methods.is_empty() { vec!["GET".to_string()] } else { methods };
            Some(RuleInput { host, port, methods, path, header })
        }
        _ => None,
    };
    let rule = match &rule_input {
        Some(input) => Some(vault::rules::parse_rule(&input.host, input.port, &input.methods, &input.path, &input.header)?),
        None => None,
    };
    let site = match (&site, &rule, kind.default_site(), &app) {
        (Some(site), _, _, _) => site.clone(),
        (None, Some(rule), _, _) => rule.host.clone(),
        (None, None, Some(default), _) => default.to_string(),
        (None, None, None, Some(app)) => app.clone(),
        (None, None, None, None) => return Err(VaultError::InvalidSecret("give --site".into())),
    };

    println!("Adding {} {name:?} for {site}", kind.label());
    if let Some(rule) = &rule {
        println!("  rule: {}", rule.describe());
        println!("  the key is sent only there, only in that header; redirects are never followed");
    }
    if let Some(username) = &username {
        println!("  username: {username}");
    }
    if let Some(spec) = vault::kinds::spec(kind) {
        // A prefix ending in `:` covers one method name (`rules::path_within`).
        let paths: Vec<String> = spec
            .path_prefixes
            .iter()
            .map(|prefix| if prefix.ends_with(':') { format!("{prefix}<method>") } else { format!("{prefix} (and below)") })
            .collect();
        println!(
            "  used only by `stream`: {} to https://{}, at {}, the token in `{}`",
            spec.methods.join(","),
            spec.hosts.join(" or https://"),
            paths.join(" or "),
            spec.set_headers.iter().map(|h| h.name).collect::<Vec<_>>().join(", ")
        );
        if let Some(refresher) = spec.refresher {
            println!("  renewed by the vault alone, at {}: nothing else may renew this login from now on", refresher.host);
            let given = if kind == Kind::GoogleAiLogin { "agy token file" } else { "auth.json" };
            println!("  (the {given} you give stops being renewable once the vault renews it)");
        }
    }
    if kind == Kind::AppSecret {
        if leasable {
            println!("  used only by `lease`: sealed to one build's own key, for at most a day; never shown");
        } else {
            println!("  stored and listed only: without --leasable no build can lease it");
        }
    }
    if kind == Kind::PersonalDetails {
        println!("  fields: {} (leave any empty)", vault::details::FIELDS.join(", "));
        println!("  stored and listed only: list shows which fields are filled, never what they say");
    }
    let stdin_value = !std::io::stdin().is_terminal();
    if stdin_value && !yes {
        return Err(VaultError::InvalidSecret("reading the value from standard input needs --yes".into()));
    }
    if !yes && !confirm("Save it?")? {
        println!("Nothing saved.");
        return Ok(());
    }
    let value = if kind == Kind::PersonalDetails && !stdin_value {
        read_details()?
    } else {
        read_hidden(prompt_for(kind))?
    };
    // R27: sent only to a daemon verified as your own user's.
    let reply = client::add(
        paths,
        &name,
        kind,
        &site,
        rule_input.as_ref(),
        username.as_deref(),
        app.as_deref(),
        leasable,
        &value,
    )?;
    drop(value);
    println!("Saved {} {:?} for {}.", reply.secret.kind.label(), reply.secret.name, reply.secret.site);
    if let Some(fields) = &reply.secret.fields {
        println!("  filled: {}", fields.join(", "));
    }
    print_backup(&reply.backup);
    Ok(())
}

/// Personal details, one hidden prompt per field; the empty ones are left out.
fn read_details() -> Result<SecretValue, VaultError> {
    let mut fields = Vec::new();
    for field in vault::details::FIELDS {
        let label = match field {
            "name" => "Name",
            "address" => "Address",
            "birthday" => "Birthday",
            _ => "Phone",
        };
        fields.push((field, read_hidden(&format!("{label} (hidden; empty to skip): "))?));
    }
    Ok(vault::details::given_from_fields(&fields))
}

fn prompt_for(kind: Kind) -> &'static str {
    match kind {
        Kind::ApiKey => "API key (hidden): ",
        Kind::Login => "Password (hidden): ",
        Kind::TwoFactor => "2FA seed, base32 or otpauth:// link (hidden): ",
        Kind::ClaudePlan => "Claude plan token, from `claude setup-token` (hidden): ",
        Kind::CodexLogin => "Codex auth.json, whole (hidden; or pipe the file in with --yes): ",
        Kind::GrokLogin => "Grok auth.json, whole (hidden; or pipe the file in with --yes): ",
        Kind::GoogleAiLogin => "agy's antigravity-oauth-token file, whole (hidden; or pipe the file in with --yes): ",
        Kind::PersonalDetails => "Personal details, a JSON object (hidden; or pipe it in with --yes): ",
        Kind::AppSecret => "App secret's value (hidden; or pipe it in with --yes): ",
        Kind::Wallet => "",
    }
}

/// A cap as typed: a decimal in dollars, gwei or ETH, into its whole units.
fn cap_units(text: &str, decimals: u32, what: &str) -> Result<u64, VaultError> {
    let units = vault::wallet::parse_amount(text.trim().trim_start_matches('$'), decimals)
        .map_err(|_| VaultError::InvalidSecret(format!("{what} is a number with at most {decimals} decimal places")))?;
    u64::try_from(units).map_err(|_| VaultError::InvalidSecret(format!("{what} is too large")))
}

/// The caps a command line asks for: each one given, else the current wallet's (`vault wallet
/// caps`), else the chain's default (`vault wallet create`). A fee cap of another chain is refused.
fn caps_from(
    chain: vault::wallet::Chain,
    per_payment: Option<&str>,
    daily: Option<&str>,
    fees: &FeeCapArgs,
    current: Option<vault::wallet::Caps>,
) -> Result<vault::wallet::Caps, VaultError> {
    use vault::wallet::Family;
    let family = chain.family();
    let given = |flag: &Option<String>, name: &str, own: Family| -> Result<Option<String>, VaultError> {
        match flag {
            Some(_) if own != family => {
                Err(VaultError::InvalidSecret(format!("--{name} is for {} wallets; this one is on {}", own.coin(), chain.label())))
            }
            other => Ok(other.clone()),
        }
    };
    // Each fee cap: (what was typed, the current value, its default, decimals, the flag).
    let pick = |typed: Option<String>, now: Option<u64>, default: &str, decimals: u32, name: &str| -> Result<u64, VaultError> {
        match (typed, now) {
            (Some(text), _) => cap_units(&text, decimals, &format!("--{name}")),
            (None, Some(units)) => Ok(units),
            (None, None) if family_owns(name, family) => cap_units(default, decimals, &format!("--{name}")),
            (None, None) => Ok(0),
        }
    };
    let max_fee_gwei = given(&fees.max_fee_gwei, "max-fee-gwei", Family::Evm)?;
    let daily_fees_eth = given(&fees.daily_fees_eth, "daily-fees-eth", Family::Evm)?;
    let max_fee_limit_trx = given(&fees.max_fee_limit_trx, "max-fee-limit-trx", Family::Tron)?;
    let daily_fees_trx = given(&fees.daily_fees_trx, "daily-fees-trx", Family::Tron)?;
    let max_priority = given(&fees.max_priority_fee_micro_lamports, "max-priority-fee-micro-lamports", Family::Solana)?;
    let daily_fees_sol = given(&fees.daily_fees_sol, "daily-fees-sol", Family::Solana)?;
    let caps = vault::wallet::Caps {
        per_payment_micros: match (per_payment, current) {
            (Some(text), _) => cap_units(text, 6, "--per-payment")?,
            (None, Some(caps)) => caps.per_payment_micros,
            (None, None) => return Err(VaultError::InvalidSecret("--per-payment is needed".into())),
        },
        daily_micros: match (daily, current) {
            (Some(text), _) => cap_units(text, 6, "--daily")?,
            (None, Some(caps)) => caps.daily_micros,
            (None, None) => return Err(VaultError::InvalidSecret("--daily is needed".into())),
        },
        max_fee_per_gas: pick(max_fee_gwei, current.map(|c| c.max_fee_per_gas), "100", 9, "max-fee-gwei")?,
        daily_fees_wei: pick(daily_fees_eth, current.map(|c| c.daily_fees_wei), "0.02", 18, "daily-fees-eth")?,
        max_fee_limit_sun: pick(max_fee_limit_trx, current.map(|c| c.max_fee_limit_sun), "30", 6, "max-fee-limit-trx")?,
        daily_fees_sun: pick(daily_fees_trx, current.map(|c| c.daily_fees_sun), "300", 6, "daily-fees-trx")?,
        max_compute_unit_price: pick(
            max_priority,
            current.map(|c| c.max_compute_unit_price),
            "1000000",
            0,
            "max-priority-fee-micro-lamports",
        )?,
        daily_fees_lamports: pick(daily_fees_sol, current.map(|c| c.daily_fees_lamports), "0.05", 9, "daily-fees-sol")?,
    };
    caps.validate(chain)?;
    Ok(caps)
}

/// Whether a fee-cap flag is the family's own (so a new wallet gets its default).
fn family_owns(flag: &str, family: vault::wallet::Family) -> bool {
    use vault::wallet::Family;
    match family {
        Family::Evm => flag.ends_with("gwei") || flag.ends_with("eth"),
        Family::Tron => flag.ends_with("trx"),
        Family::Solana => flag.ends_with("lamports") || flag.ends_with("sol"),
    }
}

fn print_wallet(secret: &vault::model::SecretSummary) {
    if let Some(wallet) = &secret.wallet {
        let family = wallet.chain.family();
        match wallet.chain.chain_id() {
            Some(id) => println!("  chain:            {} (chain id {id})", wallet.chain.label()),
            None if wallet.chain.is_test() => println!("  chain:            {} (a test network: its tokens have no value)", wallet.chain.label()),
            None => println!("  chain:            {}", wallet.chain.label()),
        }
        println!("  address:          {}", wallet.checksummed);
        println!("  caps:             {}", wallet.caps.describe(wallet.chain));
        println!(
            "  last 24 hours:    ${} paid, {} in fees at most",
            vault::wallet::decimal(wallet.spent_today_micros as u128, 6),
            family.fee_text(wallet.fees_today)
        );
    }
}

fn wallet_create(paths: &Paths, name: &str, chain: &str, per_payment: &str, daily: &str, fees: &FeeCapArgs) -> Result<(), VaultError> {
    vault::model::validate_name(name)?;
    let chain = vault::wallet::Chain::parse(chain)?;
    let caps = caps_from(chain, Some(per_payment), Some(daily), fees, None)?;
    println!("Making wallet {name:?} on {}", chain.label());
    println!("  caps:             {}", caps.describe(chain));
    println!("  its key is made in this vault and never shown or exported; it signs token payments only");
    println!("  only the recovery key can change the caps later");
    let typed = read_hidden("Paste the recovery key from the kit (AGE-SECRET-KEY-1...), hidden: ")?;
    let reply = client::wallet_create(paths, name, chain.label(), &caps, &typed)?;
    drop(typed);
    println!("Made wallet {:?} (id {}).", reply.secret.name, reply.secret.id);
    print_wallet(&reply.secret);
    let funding = match chain.family() {
        vault::wallet::Family::Evm => "USDC or USDT, and a little ETH for fees",
        vault::wallet::Family::Solana => "USDC (or USDT on mainnet), and a little SOL for fees and recipients' token accounts",
        vault::wallet::Family::Tron => "USDT, and some TRX for energy and bandwidth (a Tron address is active once it holds TRX)",
    };
    println!("Fund it by sending {funding} to the address above.");
    print_backup(&reply.backup);
    Ok(())
}

fn wallet_caps(paths: &Paths, name: &str, per_payment: Option<String>, daily: Option<String>, fees: &FeeCapArgs) -> Result<(), VaultError> {
    let listed = client::list(paths)?;
    let secret = listed.secrets.iter().find(|secret| secret.name == name).ok_or_else(|| VaultError::UnknownSecret(name.into()))?;
    let wallet = secret.wallet.as_ref().ok_or(VaultError::WrongKind)?;
    let (chain, current) = (wallet.chain, wallet.caps);
    let caps = caps_from(chain, per_payment.as_deref(), daily.as_deref(), fees, Some(current))?;
    println!("Changing the caps of wallet {name:?}");
    println!("  now:              {}", current.describe(chain));
    println!("  new:              {}", caps.describe(chain));
    let typed = read_hidden("Paste the recovery key from the kit (AGE-SECRET-KEY-1...), hidden: ")?;
    let reply = client::wallet_caps(paths, &SecretRef::Name(name.into()), &caps, &typed)?;
    drop(typed);
    println!("Caps changed; {:?} is now version {}.", reply.secret.name, reply.secret.version);
    print_wallet(&reply.secret);
    print_backup(&reply.backup);
    Ok(())
}

fn delete(paths: &Paths, name: &str, yes: bool) -> Result<(), VaultError> {
    if !yes && !confirm(&format!("Delete {name:?}? Earlier backups keep it."))? {
        println!("Nothing deleted.");
        return Ok(());
    }
    let reply = client::delete(paths, &SecretRef::Name(name.into()))?;
    println!("Deleted {name:?}.");
    print_backup(&reply.backup);
    Ok(())
}

fn rename(paths: &Paths, name: &str, new_name: &str) -> Result<(), VaultError> {
    let reply = client::rename(paths, &SecretRef::Name(name.into()), new_name)?;
    println!(
        "Renamed {name:?} to {:?}: id {} kept, now version {}.",
        reply.secret.name, reply.secret.id, reply.secret.version
    );
    print_backup(&reply.backup);
    Ok(())
}

fn list(paths: &Paths) -> Result<(), VaultError> {
    let reply = client::list(paths)?;
    if reply.secrets.is_empty() {
        println!("No secrets yet.");
        return Ok(());
    }
    println!("{:<32}  {:<24} {:<16} {:>3}  SITE", "ID", "NAME", "KIND", "VER");
    for secret in reply.secrets {
        // Personal details: which fields are filled, never what they say.
        let mut fields = secret.fields.as_ref().map(|fields| format!("  (filled: {})", fields.join(", "))).unwrap_or_default();
        // App secrets: the application, and whether builds may lease it; never the value.
        if let Some(app) = &secret.app {
            let lease = if secret.leasable == Some(true) { "leasable" } else { "not leasable" };
            fields = format!("  (app {app}, {lease})");
        }
        // Wallets: the address and the caps; never the key.
        if let Some(wallet) = &secret.wallet {
            fields = format!(
                "  ({} ${}/payment, ${}/day; ${} today)",
                wallet.checksummed,
                vault::wallet::decimal(wallet.caps.per_payment_micros as u128, 6),
                vault::wallet::decimal(wallet.caps.daily_micros as u128, 6),
                vault::wallet::decimal(wallet.spent_today_micros as u128, 6)
            );
        }
        println!(
            "{:<32}  {:<24} {:<16} {:>3}  {}{}",
            secret.id,
            secret.name,
            secret.kind.label(),
            secret.version,
            secret.site,
            fields
        );
    }
    Ok(())
}

fn health(paths: &Paths) -> Result<(), VaultError> {
    let reply = client::health(paths)?;
    if reply.credentials.is_empty() {
        println!("No Claude plans, Codex, Grok or Google AI logins in the vault.");
        return Ok(());
    }
    println!("{:<24} {:<15} {:>3}  {:<8} {:<6} {:<21} RENEWED", "NAME", "KIND", "VER", "TOKEN", "STATUS", "SEEN");
    for c in reply.credentials {
        println!(
            "{:<24} {:<15} {:>3}  {:<8} {:<6} {:<21} {}",
            c.name,
            c.kind.label(),
            c.version,
            c.state.label(),
            c.status.map_or("-".into(), |s| s.to_string()),
            c.checked_at.unwrap_or_else(|| "-".into()),
            match c.refresh.as_str() {
                "never" => "never (a new sign-in replaces it)",
                "awaiting_claim" => "not yet: imported, waiting for the host's claim_refresh",
                _ => "by the vault",
            }
        );
        if let Some(reason) = c.reason {
            println!("{:<24} {reason}", "");
        }
    }
    Ok(())
}

/// Who owns a path and its mode, for `status`.
fn owner_and_mode(path: &std::path::Path) -> String {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let owner = store::account_by_uid(meta.uid()).map_or(meta.uid().to_string(), |a| a.name);
            format!("{owner}, mode {:o}", meta.mode() & 0o7777)
        }
        Err(_) => "missing".into(),
    }
}

/// `vault status --json`: always one JSON object on standard output, and success, whatever the
/// vault's state; `healthy` and `problems` say what is wrong.
fn status_json(paths: &Paths) -> Result<(), VaultError> {
    let status = vault::report::gather_status(paths);
    let text = serde_json::to_string_pretty(&status).map_err(|_| VaultError::Io("JSON encoding".into()))?;
    println!("{text}");
    Ok(())
}

fn status(paths: &Paths) -> Result<(), VaultError> {
    println!("Volgenic vault {} (commit {})", vault::VERSION, vault::GIT_COMMIT);
    let installed = paths.program.exists();
    if installed {
        println!("  installed program: {}", paths.program.display());
    } else {
        println!("  installed program: none. Install with `vault install`.");
    }
    println!("  vault folder:      {} ({})", paths.dir.display(), owner_and_mode(&paths.dir));
    if !installed {
        return Ok(());
    }
    let reply = match client::status(paths) {
        Ok(reply) => reply,
        Err(error) => {
            println!("  daemon:            {error}");
            if let Ok(log) = std::fs::read_to_string(&paths.daemon_log) {
                println!("  last lines of {}:", paths.daemon_log.display());
                let lines: Vec<&str> = log.lines().collect();
                for line in &lines[lines.len().saturating_sub(5)..] {
                    println!("    {line}");
                }
            }
            return Ok(());
        }
    };
    println!(
        "  daemon:            answering as user ID {}, pid {}, version {}, protocol {}, writes format {}",
        reply.uid,
        reply.pid,
        reply.version,
        vault::protocol::PROTOCOL_VERSION,
        reply.format
    );
    println!("  vault key:         {}", reply.key_protection);
    println!("  local backups:     {}", reply.local_backups);
    let Some(opened) = &reply.vault else {
        println!("\nNo vault on this {MACHINE} yet.");
        if reply.restore_point {
            println!("`vault reset` kept a restore point: restore it with `vault restore`.");
        } else {
            println!("Restore one with `vault restore FILE`.");
        }
        return Ok(());
    };
    println!("\nVault {}", opened.vault_identity);
    println!("  identity:          {} (stays the same through restores)", opened.vault_identity);
    println!("  this copy:         {} (new at every restore; names the backup files)", opened.vault_id);
    println!("  file format:       {}", opened.format);
    println!("  created:           {}", opened.created_at);
    println!("  recovery key:      fingerprint {}", opened.recovery_fingerprint);
    match &opened.intake_recipient {
        Some(public) => println!(
            "  intake key:        {public} (fingerprint {}; Volgenic's app seals values to it)",
            vault::backup::fingerprint(public)
        ),
        None => println!("  intake key:        none yet (the daemon makes one when it next starts)"),
    }
    println!(
        "  Recovery Kit:      {}",
        if opened.kit_confirmed { "confirmed" } else { "not confirmed yet (`vault confirm-kit`; see the warning below)" }
    );
    if let (false, Some(kit)) = (opened.kit_confirmed, &opened.kit_path) {
        println!("                     the kit file: {kit}");
    }
    let kinds: Vec<String> = opened.by_kind.iter().map(|(k, n)| format!("{n} {}", k.label())).collect();
    println!("  secrets:           {} ({})", opened.secrets, kinds.join(", "));
    println!("  changes so far:    {}", opened.generation);
    match &opened.last_backup {
        Some(backup) if backup.ok => println!(
            "  last backup:       OK, generation {} at {}, read back and decrypted",
            backup.generation, backup.at
        ),
        Some(backup) => println!(
            "  last backup:       FAILED at {}: {} (changes refused until a backup succeeds)",
            backup.at, backup.detail
        ),
        None => println!("  last backup:       none yet"),
    }
    println!("  mirror folder:     {}", opened.mirror_dir);
    match &reply.mirror {
        None => println!("  last mirror:       none yet. Run `vault install-mirror`."),
        Some(mirror) if mirror.ok => {
            let behind = mirror.newest_generation.map_or(opened.generation, |g| opened.generation.saturating_sub(g));
            println!(
                "  last mirror:       OK at {}, newest generation {} ({}), checked by SHA-256",
                mirror.at,
                mirror.newest_generation.map_or("none".into(), |g| g.to_string()),
                if behind == 0 { "up to date".to_string() } else { format!("{behind} behind") }
            );
        }
        Some(mirror) => println!("  last mirror:       FAILED at {}: {}", mirror.at, mirror.detail),
    }
    println!("                     (reported by the mirror agent; any program running as you could send one)");
    match (&opened.audit_lines, &opened.audit_problem) {
        (Some(lines), _) => match opened.audit_files {
            Some(files) if files > 1 => println!("  audit log:         {lines} lines in {files} files, hash chain intact"),
            _ => println!("  audit log:         {lines} lines, hash chain intact"),
        },
        (None, Some(problem)) => println!("  audit log:         PROBLEM: {problem}"),
        _ => {}
    }
    if !opened.recent_changes.is_empty() {
        println!("  recent changes:");
        for change in &opened.recent_changes {
            println!("    {change}");
        }
    }
    // The Recovery Kit, FileVault and automatic login, loudly (#7689).
    print!("{}", vault::report::stolen_disk_banner(&vault::report::gather_status(paths).problems));
    Ok(())
}

fn show_audit(paths: &Paths, all: bool) -> Result<(), VaultError> {
    let reply = client::audit(paths, all)?;
    if let Some(problem) = &reply.problem {
        println!("PROBLEM: {problem}");
        return Ok(());
    }
    for line in &reply.lines {
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
    let shown = reply.lines.len();
    println!(
        "-- {} lines, hash chain intact{}",
        reply.total,
        if shown < reply.total { format!("; showing the last {shown}") } else { String::new() }
    );
    Ok(())
}

fn verify_backup(paths: &Paths, with_recovery_key: bool) -> Result<(), VaultError> {
    let check = client::verify(paths)?;
    println!("Backup {} (checked by the daemon)", check.file);
    println!("  generation {}, written {} (newest)", check.generation, check.written_at);
    println!("  decrypted with the vault's check key: OK, {} secrets", check.secrets);
    println!(
        "  matches the vault: {}",
        if check.matches_vault { "yes, every id, name, rule and value" } else { "NO (the vault changed since)" }
    );
    if !with_recovery_key {
        println!("  recovery key: not checked (add --with-recovery-key)");
        return if check.matches_vault { Ok(()) } else { Err(VaultError::BackupMismatch) };
    }
    let fingerprint = client::status(paths)?.vault.map(|v| v.recovery_fingerprint).ok_or(VaultError::NotInitialized)?;
    let (file, data) = client::read_newest(paths)?;
    let typed = read_hidden("Recovery key (AGE-SECRET-KEY-1...), hidden: ")?;
    // R27: this check changes nothing, so it runs here and the key never crosses the socket.
    let opens = client::recovery_key_opens(&data, typed, &fingerprint);
    println!("  recovery key opens {file}: {}", if opens { "yes" } else { "NO" });
    if !check.matches_vault {
        return Err(VaultError::BackupMismatch);
    }
    if !opens {
        return Err(VaultError::WrongRecoveryKey);
    }
    Ok(())
}

fn backup_now(paths: &Paths) -> Result<(), VaultError> {
    let reply = client::backup(paths)?;
    print_backup(&reply.backup);
    if reply.backup.ok { Ok(()) } else { Err(VaultError::BackupFailed(reply.backup.detail)) }
}

fn restore(paths: &Paths, file: Option<PathBuf>) -> Result<(), VaultError> {
    let status = client::status(paths)?;
    if status.vault.is_some() {
        return Err(VaultError::AlreadyInitialized);
    }
    let file = match file {
        Some(path) => {
            #[cfg(target_os = "macos")]
            {
                println!("This reads the file you named from this terminal. In iCloud Drive, Desktop, Documents");
                println!("or Downloads, macOS may first ask whether this terminal app may access it.");
            }
            let data = std::fs::read(&path)
                .map_err(|e| VaultError::BackupFailed(format!("can't read {}: {e}", path.display())))?;
            Some((path.display().to_string(), data))
        }
        None if !status.restore_point => {
            return Err(VaultError::InvalidSecret(
                format!("no restore point on this {MACHINE}; name a backup file: vault restore FILE"),
            ));
        }
        None => {
            println!("Restoring the backup `vault reset` kept in the vault folder.");
            None
        }
    };
    let typed = read_hidden("Recovery key (AGE-SECRET-KEY-1...), hidden: ")?;
    // R27: sent only to a daemon verified as your own user's.
    let reply = client::restore(paths, &typed, file)?;
    drop(typed);
    println!(
        "Restored vault {} as copy {}, from copy {} generation {} (format {}).",
        reply.vault_identity, reply.vault_id, reply.from_vault_id, reply.from_generation, reply.from_format
    );
    if reply.from_format < 2 {
        println!("  same identity; the backup was format {}, so its secrets got their ids now", reply.from_format);
    } else {
        println!("  same identity, secret ids and versions");
    }
    println!("  new vault key and copy id; older backups stay as they are");
    for secret in &reply.secrets {
        println!("  {:<32}  {:<24} {:<8} {}", secret.id, secret.name, secret.kind.label(), secret.site);
    }
    print_backup(&reply.backup);
    if reply.backup.ok { Ok(()) } else { Err(VaultError::BackupFailed(reply.backup.detail)) }
}

fn reset(paths: &Paths) -> Result<(), VaultError> {
    let status = client::status(paths)?;
    let vault = status.vault.ok_or(VaultError::NotInitialized)?;
    if vault.generation == 1 && !vault.kit_confirmed && vault.secrets == 0 {
        println!("This vault never held a secret (nothing has changed since it was made), so it can be");
        println!("removed without the recovery key. The kit file, if still there, is deleted too.");
        if !confirm("Remove it?")? {
            println!("Nothing changed.");
            return Ok(());
        }
        let reply = client::reset(paths, None)?;
        delete_kit(reply.kit_path.as_deref());
        println!("Unused vault removed. Restore one with `vault restore FILE`, or make a new one with");
        println!("`vault install`.");
        return Ok(());
    }
    println!("This removes the vault from this {MACHINE} (its vault file and key) so a backup can");
    println!("be restored. The backups and the audit log stay. It needs the");
    println!("recovery key, and it only goes ahead if the newest backup opens with that key and");
    println!("matches the vault.");
    if !confirm("Go ahead?")? {
        println!("Nothing changed.");
        return Ok(());
    }
    let typed = read_hidden("Recovery key (AGE-SECRET-KEY-1...), hidden: ")?;
    let reply = client::reset(paths, Some(&typed))?;
    drop(typed);
    println!(
        "Vault removed from this {MACHINE}. Its newest backup ({}) is kept in the vault folder as a",
        reply.newest_file.unwrap_or_default()
    );
    println!("restore point. Restore it with:");
    println!("  vault restore");
    Ok(())
}
