//! Key protection: the vault key is 32 random bytes, sealed to this machine's hardware when it
//! has the hardware (the Secure Enclave on a Mac, the TPM on Linux), else kept as a mode-0600 file
//! next to the vault file, in the owner's own folder. The daemon unseals it at every start with no
//! prompt, so agents keep working unattended. What sealing adds on both systems: a copy of the disk
//! (a stolen drive, a Time Machine or home-folder backup) can't open the vault on any other
//! machine. What it doesn't: anything running as the owner on this machine can have it unsealed,
//! as it could read the plain file. This module is the only code that touches where the key is
//! kept.
//!
//! **A new key is sealed in memory (#7689).** On a machine that can seal, `store_new` seals the
//! new key straight from memory, checks the round trip, and never writes it in plain, so no
//! backup or snapshot ever holds it. Only a machine that can't seal gets the 0600 file.
//!
//! **A key that was a plain file is replaced, not wrapped.** A key that sat in `vault.key` is in
//! every Time Machine backup and APFS snapshot made since, so sealing that same key would protect
//! nothing in them. `vault install` (`vault::reseal`, with the daemon stopped) makes a new key,
//! seals it as `<sealed>.new`, encrypts the vault file again under it, renames `<sealed>.new` to
//! `<sealed>`, and only then unlinks the old key. A crash between steps loses nothing: `load` tries
//! each key it finds and keeps the one that opens the vault file.
//!
//! **A key must open the vault file.** `load` accepts a key (sealed, pending or plain) only when
//! it decrypts `vault.bin`, says loudly in the daemon's log when it had to use anything but the
//! sealed key, and never writes over a sealed key that still opens the vault.
//!
//! **On a Mac, wrapped by the Secure Enclave.** `enclave` makes a P-256 key in this Mac's Secure
//! Enclave and wraps the vault key with it, into `vault.key.se`, bound to the vault's id. The
//! Enclave key never leaves the Enclave: the file holds only the Enclave's encrypted handle to it,
//! usable by this Mac's Enclave alone, after the first unlock since boot, and never asks for a
//! fingerprint or a password. No Keychain item is made. On a Mac without a Secure Enclave (an
//! Intel Mac without a T2 chip) the key stays the 0600 file, and `vault status` says so.
//!
//! **On Linux, sealed to the TPM when there is one.** `sealed` hands the key, through a pipe, to
//! `systemd-creds --user encrypt --with-key=host+tpm2` (systemd 256 or later, a TPM 2.0), which
//! writes `vault.key.cred`: the key encrypted to this machine's TPM and its host secret, and bound
//! to the owner's user. A user-scoped credential can't be `tpm2` alone: `systemd-creds` refuses
//! it ("Selected key not available in --uid= scoped mode"), because the user scoping is keyed off
//! the host secret. The daemon unseals it at every start with `systemd-creds --user decrypt`,
//! unattended, which is what lets the vault come back after a reboot with nobody logged in.
//! Without `systemd-creds --user` or a TPM, the key stays the 0600 file.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::secret::SecretValue;

/// The vault key, in the vault folder.
pub const KEY_FILE: &str = "vault.key";

/// The vault key sealed to the TPM by `systemd-creds` (Linux).
pub const SEALED_FILE: &str = "vault.key.cred";

/// The vault key wrapped by the Secure Enclave (macOS).
pub const ENCLAVE_FILE: &str = "vault.key.se";

/// A new key sealed while the vault file is encrypted again under it (`vault::reseal`).
const SEALED_PENDING: &str = "vault.key.cred.new";
const ENCLAVE_PENDING: &str = "vault.key.se.new";

#[cfg(target_os = "macos")]
mod enclave;

/// This system's sealed key file, and the pending one.
#[cfg(target_os = "macos")]
const SEALED: &str = ENCLAVE_FILE;
#[cfg(target_os = "macos")]
const PENDING: &str = ENCLAVE_PENDING;
#[cfg(not(target_os = "macos"))]
const SEALED: &str = SEALED_FILE;
#[cfg(not(target_os = "macos"))]
const PENDING: &str = SEALED_PENDING;

/// What sealed it, in `vault status`'s words.
#[cfg(target_os = "macos")]
const SEALED_BY: &str = "wrapped by this Mac's Secure Enclave";
#[cfg(not(target_os = "macos"))]
const SEALED_BY: &str = "sealed to this machine's TPM 2.0 by systemd-creds";

/// `kind` in `vault status --json` for a sealed key the daemon unsealed.
const SEALED_KIND: &str = if cfg!(target_os = "macos") { "secure_enclave" } else { "tpm2" };

/// The largest key file read: the Enclave's handle is a few hundred bytes, a TPM credential a
/// few kilobytes.
const MAX_KEY_FILE: usize = 16384;

/// Which file the vault key came from, in this process: `load` sets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The sealed file (`vault.key.se`, `vault.key.cred`).
    Sealed,
    /// The pending sealed file of an interrupted re-key (`<sealed>.new`).
    Pending,
    /// The plain 0600 file.
    Plain,
}

impl Source {
    pub fn word(self) -> &'static str {
        match self {
            Source::Sealed => "sealed",
            Source::Pending => "pending",
            Source::Plain => "plain",
        }
    }

    fn file(self) -> &'static str {
        match self {
            Source::Sealed => SEALED,
            Source::Pending => PENDING,
            Source::Plain => KEY_FILE,
        }
    }
}

/// `Source` as a number, 0 before `load` ran.
static LOADED: AtomicU8 = AtomicU8::new(0);

/// Where this process's `load` got the vault key, for the daemon's status: `sealed`, `pending`,
/// `plain`, or nothing before a key was loaded.
pub fn loaded_from() -> Option<&'static str> {
    match LOADED.load(Ordering::Relaxed) {
        1 => Some(Source::Sealed.word()),
        2 => Some(Source::Pending.word()),
        3 => Some(Source::Plain.word()),
        _ => None,
    }
}

fn set_loaded(source: Source) {
    let n = match source {
        Source::Sealed => 1,
        Source::Pending => 2,
        Source::Plain => 3,
    };
    LOADED.store(n, Ordering::Relaxed);
}

/// Says something the person must see in the daemon's log (or the install's stderr).
fn warn(message: &str) {
    eprintln!("{} vault: WARNING: vault key: {message}", crate::now_rfc3339());
}

/// Why this machine can't seal the key, or nothing when it can.
pub fn seal_ready() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    return sealed::ready().map(|_| ());
    #[cfg(target_os = "macos")]
    return enclave::ready();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Err("this system has nothing to seal the key to".into())
}

fn exists(dir: &Path, name: &str) -> bool {
    fs::symlink_metadata(dir.join(name)).is_ok()
}

/// Where the vault key is kept, for `vault status` and the daemon's log: the files there are.
pub fn describe(dir: &Path) -> String {
    let pending = if exists(dir, PENDING) { format!(", and a pending new key ({PENDING}) of an interrupted re-key") } else { String::new() };
    match (exists(dir, SEALED), exists(dir, KEY_FILE)) {
        (true, false) => format!("{SEALED_BY} ({SEALED}); no plain copy{pending}"),
        (true, true) => format!(
            "{SEALED_BY} ({SEALED}), and a plain {KEY_FILE} is still there{pending} (`vault install` replaces the key and removes it)"
        ),
        (false, true) => format!("vault key in a mode-600 file next to the vault file, not sealed to this machine{pending}"),
        (false, false) if !pending.is_empty() => format!("only a pending new key ({PENDING}) of an interrupted re-key"),
        (false, false) => "no vault key".into(),
    }
}

/// Where the vault key is kept, as plain values for `vault status --json`. Information only.
pub struct KeyState {
    /// `tpm2` (sealed by systemd-creds, Linux) or `secure_enclave` (wrapped by the Secure
    /// Enclave, macOS) only when the running daemon unsealed its key from that file;
    /// `unchecked` (a sealed file is there, but no running daemon says it opened it); `file` (the
    /// 0600 key file, or a sealed file the daemon couldn't use) or `none` (no key).
    pub kind: &'static str,
    /// For `file` and `unchecked`: why it isn't (known to be) sealed.
    pub reason: Option<String>,
    /// A sealed key and a plain copy are both there (a key not yet replaced, or an interrupted
    /// re-key).
    pub plain_copy_left: bool,
    /// For `file`: this machine could seal it now (`vault install` would).
    pub sealable: bool,
    /// The running daemon got its key from the plain file although a sealed one is there.
    pub sealed_unusable: bool,
    /// `describe`, the sentence `vault status` prints.
    pub detail: String,
}

/// The key's state from the files and from what the running daemon said it loaded (`daemon`:
/// `loaded_from` there, `None` when no daemon answered or it is too old to say).
pub fn state(dir: &Path, daemon: Option<&str>) -> KeyState {
    let plain = exists(dir, KEY_FILE);
    let sealed = exists(dir, SEALED) || exists(dir, PENDING);
    let detail = describe(dir);
    let base = KeyState { kind: "none", reason: None, plain_copy_left: sealed && plain, sealable: false, sealed_unusable: false, detail };
    match daemon {
        Some("sealed" | "pending") => KeyState { kind: SEALED_KIND, ..base },
        Some(_) if sealed => KeyState {
            kind: "file",
            reason: Some(format!("the sealed key ({SEALED}) didn't open the vault, so the daemon is running on the plain {KEY_FILE}")),
            sealed_unusable: true,
            ..base
        },
        None if sealed => KeyState {
            kind: "unchecked",
            reason: Some("a sealed key is there, but no running daemon has opened the vault with it yet".into()),
            ..base
        },
        _ if !plain => base,
        _ => {
            let (reason, sealable) = match seal_ready() {
                Ok(()) => ("not sealed yet, though this machine can seal it: `vault install` replaces it with a sealed key".to_string(), true),
                Err(why) => (why, false),
            };
            KeyState { kind: "file", reason: Some(reason), sealable, ..base }
        }
    }
}

pub fn key_exists(dir: &Path) -> bool {
    [KEY_FILE, SEALED_FILE, ENCLAVE_FILE, SEALED_PENDING, ENCLAVE_PENDING].iter().any(|name| exists(dir, name))
}

/// Stores the key of a new vault (`vault_id`'s): sealed straight from memory when this machine
/// can seal, so it is never written in plain; else a mode-0600 file. Fails if a key is already
/// stored. Says how the key is kept.
pub fn store_new(dir: &Path, vault_id: &str, key: &SecretValue) -> Result<String, VaultError> {
    if key_exists(dir) {
        return Err(VaultError::AlreadyInitialized);
    }
    match seal_to(dir, SEALED, vault_id, key, false) {
        Ok(()) => Ok(format!("{SEALED_BY} ({SEALED}); never written in plain")),
        Err(why) => {
            write_plain(dir, key)?;
            Ok(format!("mode-600 file ({why})"))
        }
    }
}

/// Writes the key as the mode-0600 file. The key-file call site of `expose` in R1.
fn write_plain(dir: &Path, key: &SecretValue) -> Result<(), VaultError> {
    // `create_new` (O_EXCL) refuses an existing file or symbolic link at the path.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join(KEY_FILE))
        .map_err(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { VaultError::AlreadyInitialized } else { e.into() })?;
    file.write_all(key.expose())?;
    file.sync_all()?;
    Ok(())
}

/// Refuses a key file that isn't a plain file of the running user's with no group or other bits.
#[cfg(target_os = "linux")]
fn check_own_file(path: &Path) -> Result<(), VaultError> {
    let meta = fs::symlink_metadata(path).map_err(|_| VaultError::KeyProtection)?;
    check_meta(path, &meta)
}

fn check_meta(path: &Path, meta: &fs::Metadata) -> Result<(), VaultError> {
    if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::getuid() } {
        return Err(VaultError::UnsafeVaultFolder(format!("{} must be a 0600 file of yours", path.display())));
    }
    Ok(())
}

/// Reads a key file of the owner's: opened without following a symbolic link (`O_NOFOLLOW`),
/// never blocking on a FIFO, then checked on the open handle (`fstat`: a plain file, the running
/// user's, no group or other bits, at most `MAX_KEY_FILE` bytes), so nothing can swap the file
/// between the check and the read. Into a buffer sized up front and wiped on drop (R1).
fn read_own(path: &Path) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => VaultError::UnsafeVaultFolder(format!("{} is a symbolic link", path.display())),
            _ => VaultError::from(e),
        })?;
    let meta = file.metadata()?;
    check_meta(path, &meta)?;
    if meta.len() as usize > MAX_KEY_FILE {
        return Err(VaultError::SealedKey(format!("{} is too large to be a key file", path.display())));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_KEY_FILE + 1));
    (&mut file).take(MAX_KEY_FILE as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > MAX_KEY_FILE {
        return Err(VaultError::SealedKey(format!("{} is too large to be a key file", path.display())));
    }
    Ok(buf)
}

fn load_plain(dir: &Path) -> Result<SecretValue, VaultError> {
    let buf = read_own(&dir.join(KEY_FILE))?;
    if buf.len() != 32 {
        return Err(VaultError::KeyProtection);
    }
    Ok(SecretValue::from_vec(buf.to_vec()))
}

/// Unseals a sealed key file of vault `vault_id`, and says whether it is in an older format to
/// write again.
fn unseal(path: &Path, vault_id: &str) -> Result<(SecretValue, bool), VaultError> {
    #[cfg(target_os = "macos")]
    return enclave::unseal(path, vault_id);
    #[cfg(target_os = "linux")]
    {
        let _ = vault_id;
        return sealed::unseal(path).map(|key| (key, false));
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (path, vault_id);
        Err(VaultError::SealedKey("this system has nothing to seal the key to".into()))
    }
}

/// Seals `key` (of vault `vault_id`) from memory into `dir/name`: sealed to a temporary file,
/// read back and unsealed, and only when that gives back `key` is it put in place, by a hard link
/// that fails if `name` exists (`replace` false), or by a rename over it (`replace` true, only for
/// writing a sealed key that opens the vault again in the current format). Any failure leaves
/// `name` as it was and removes the temporary file.
fn seal_to(dir: &Path, name: &str, vault_id: &str, key: &SecretValue, replace: bool) -> Result<(), String> {
    seal_ready()?;
    let target = dir.join(name);
    let temp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    let _ = fs::remove_file(&temp);
    let fail = |why: String| {
        let _ = fs::remove_file(&temp);
        why
    };
    #[cfg(target_os = "macos")]
    enclave::seal(&temp, vault_id, key).map_err(fail)?;
    #[cfg(target_os = "linux")]
    sealed::seal(&temp, key).map_err(fail)?;
    match unseal(&temp, vault_id) {
        Ok((back, _)) if back.same_as(key) => {}
        Ok(_) => return Err(fail("the sealed key didn't unseal to the same key".into())),
        Err(error) => return Err(fail(error.to_string())),
    }
    let placed = if replace { fs::rename(&temp, &target) } else { fs::hard_link(&temp, &target) };
    if let Err(error) = placed {
        return Err(fail(format!("couldn't put {name} in place: {error}")));
    }
    let _ = fs::remove_file(&temp);
    sync_dir(dir);
    Ok(())
}

fn sync_dir(dir: &Path) {
    if let Ok(folder) = fs::File::open(dir) {
        let _ = folder.sync_all();
    }
}

/// Reads the vault key of vault `vault_id`, accepting it only when `open` decrypts the vault file
/// with it: the sealed key first, then a pending one (a re-key interrupted after the vault file
/// was encrypted again), then the plain file (a machine that can't seal, or a key not yet
/// replaced). Anything but the sealed key, when a sealed key is there, is said loudly in the log.
/// A sealed file in an older format that opens the vault is written again in the current one.
/// `open` returning `VaultFileCorrupt` means "not this key"; any other error stops here.
pub fn load<T>(
    dir: &Path,
    vault_id: &str,
    open: impl Fn(&SecretValue) -> Result<T, VaultError>,
) -> Result<(SecretValue, T, Source), VaultError> {
    let sealed_there = exists(dir, SEALED);
    let mut first_error: Option<VaultError> = None;
    for source in [Source::Sealed, Source::Pending, Source::Plain] {
        if !exists(dir, source.file()) {
            continue;
        }
        let (key, legacy) = match source {
            Source::Plain => match load_plain(dir) {
                Ok(key) => (key, false),
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            },
            _ => match unseal(&dir.join(source.file()), vault_id) {
                Ok(found) => found,
                Err(error) => {
                    if source == Source::Sealed {
                        warn(&format!("{SEALED} couldn't be unsealed: {error}"));
                    }
                    first_error.get_or_insert(error);
                    continue;
                }
            },
        };
        match open(&key) {
            Ok(value) => {
                if source != Source::Sealed && sealed_there {
                    warn(&format!(
                        "{SEALED} didn't open the vault, so it was opened with {}; run `vault install` to seal a new key",
                        source.file()
                    ));
                }
                if legacy {
                    match seal_to(dir, SEALED, vault_id, &key, true) {
                        Ok(()) => warn(&format!("{SEALED} was in an older format; it is written again, bound to this vault")),
                        Err(why) => warn(&format!("{SEALED} is in an older format and couldn't be written again: {why}")),
                    }
                }
                set_loaded(source);
                return Ok((key, value, source));
            }
            Err(VaultError::VaultFileCorrupt) => {
                first_error.get_or_insert(match source {
                    Source::Plain => VaultError::KeyProtection,
                    _ => VaultError::SealedKey(format!("{} doesn't open the vault file", source.file())),
                });
            }
            Err(error) => return Err(error),
        }
    }
    Err(first_error.unwrap_or(VaultError::KeyProtection))
}

/// Seals `key`, a new key for vault `vault_id`, as the pending file (`vault::reseal`'s first
/// step), never in plain. A stale pending file (one that didn't open the vault) is removed first.
pub fn seal_pending(dir: &Path, vault_id: &str, key: &SecretValue) -> Result<(), String> {
    discard_pending(dir);
    seal_to(dir, PENDING, vault_id, key, false)
}

/// Removes the pending file: called only when the vault file isn't encrypted under it.
pub fn discard_pending(dir: &Path) {
    let _ = fs::remove_file(dir.join(PENDING));
}

/// `vault::reseal`'s last step, once the vault file is encrypted under the pending key: the
/// pending file becomes the sealed one (the sealed key it replaces no longer opens the vault),
/// then the old plain key is unlinked.
pub fn commit_pending(dir: &Path) -> Result<(), String> {
    fs::rename(dir.join(PENDING), dir.join(SEALED)).map_err(|e| format!("couldn't put the new sealed key in place: {e}"))?;
    sync_dir(dir);
    remove_plain(dir)
}

/// Unlinks the plain key file (the sealed key opens the vault). Unlinked, never overwritten in
/// place: an overwrite that a crash interrupts would leave a damaged key, and on an SSD or APFS
/// it doesn't reach the old blocks anyway.
pub fn remove_plain(dir: &Path) -> Result<(), String> {
    match fs::remove_file(dir.join(KEY_FILE)) {
        Ok(()) => {
            sync_dir(dir);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("the plain key file wasn't removed: {error}")),
    }
}

/// Removes temporary files a seal left behind when it was interrupted (`.vault.key.*.tmp-*`).
pub fn clean_temps(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".vault.key.") && name.contains(".tmp-") {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Removes the vault key, plain and sealed (only `vault reset`, after the recovery key is proven).
pub fn remove(dir: &Path) -> Result<(), VaultError> {
    clean_temps(dir);
    for name in [SEALED_FILE, ENCLAVE_FILE, SEALED_PENDING, ENCLAVE_PENDING, KEY_FILE] {
        match fs::remove_file(dir.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Sealing the key with `systemd-creds` (Linux only).
#[cfg(target_os = "linux")]
mod sealed {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::fs;

    use zeroize::Zeroizing;

    use super::check_own_file;
    use crate::error::VaultError;
    use crate::secret::SecretValue;

    /// The credential's name, bound into it: a credential made for something else won't open.
    const CREDENTIAL_NAME: &str = "volgenic-vault.key";

    /// `systemd-creds` at its fixed place, never found through `$PATH` (R15).
    fn tool() -> Option<PathBuf> {
        ["/usr/bin/systemd-creds", "/bin/systemd-creds"].into_iter().map(PathBuf::from).find(|path| path.is_file())
    }

    /// Why the key can't be sealed here, or the tool to seal it with.
    pub(super) fn ready() -> Result<PathBuf, String> {
        let tool = tool().ok_or("systemd-creds isn't installed")?;
        let out = Command::new(&tool)
            .arg("has-tpm2")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("systemd-creds didn't run: {e}"))?;
        if !out.status.success() {
            return Err("no usable TPM 2.0 (`systemd-creds has-tpm2`)".into());
        }
        Ok(tool)
    }

    /// Unseals the key to this process's memory, through a pipe (never an argument, the
    /// environment or a file, R2).
    fn decrypt(tool: &Path, sealed: &Path) -> Result<SecretValue, VaultError> {
        let mut child = Command::new(tool)
            .args(["--user", "decrypt", &format!("--name={CREDENTIAL_NAME}")])
            .arg(sealed)
            .arg("-")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| VaultError::SealedKey(format!("systemd-creds didn't run: {e}")))?;
        // Into a fixed buffer, wiped on drop: a growing Vec would leave copies behind (R1).
        let mut key = Zeroizing::new([0u8; 33]);
        let mut len = 0;
        if let Some(mut stdout) = child.stdout.take() {
            while len < key.len() {
                match stdout.read(&mut key[len..]) {
                    Ok(0) => break,
                    Ok(n) => len += n,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            // Drain anything past 33 bytes, so the child can finish; it can't be a 32-byte key.
            let mut rest = Zeroizing::new([0u8; 256]);
            while matches!(stdout.read(&mut rest[..]), Ok(n) if n > 0) {
                len = key.len();
            }
        }
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        let status = child.wait().map_err(|e| VaultError::SealedKey(format!("systemd-creds didn't finish: {e}")))?;
        if !status.success() {
            return Err(VaultError::SealedKey(format!("systemd-creds couldn't unseal it: {}", stderr.trim())));
        }
        if len != 32 {
            return Err(VaultError::SealedKey("the unsealed key isn't 32 bytes".into()));
        }
        Ok(SecretValue::from_vec(key[..32].to_vec()))
    }

    pub fn unseal(sealed: &Path) -> Result<SecretValue, VaultError> {
        check_own_file(sealed)?;
        let tool = tool().ok_or_else(|| VaultError::SealedKey("systemd-creds isn't installed".into()))?;
        decrypt(&tool, sealed)
    }

    /// Seals `key` to the TPM into `temp` (mode 0600), the key handed over through a pipe, never
    /// a file (R2). The caller checks the round trip.
    pub fn seal(temp: &Path, key: &SecretValue) -> Result<(), String> {
        let tool = ready()?;
        let mut child = Command::new(&tool)
            // `host+tpm2`, not `tpm2`: in user scope `systemd-creds` allows only host-bound keys.
            .args(["--user", "encrypt", "--with-key=host+tpm2", &format!("--name={CREDENTIAL_NAME}"), "-"])
            .arg(temp)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("systemd-creds didn't run: {e}"))?;
        // The TPM seal's call site of `expose` in R1: the key goes to systemd-creds, nowhere else.
        let handed = match child.stdin.take() {
            Some(mut stdin) => stdin.write_all(key.expose()),
            None => Err(std::io::ErrorKind::BrokenPipe.into()),
        };
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        let status = child.wait().map_err(|e| format!("systemd-creds didn't finish: {e}"))?;
        handed.map_err(|e| format!("couldn't hand the key to systemd-creds: {e}"))?;
        if !status.success() {
            return Err(format!(
                "systemd-creds --user encrypt --with-key=host+tpm2 failed (it needs systemd 256 or later): {}",
                stderr.trim()
            ));
        }
        fs::set_permissions(temp, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())
    }
}
